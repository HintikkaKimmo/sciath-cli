"""
HTTP client for the Sciath API.

All requests go through _request() which centralises:
  - auth header injection
  - typed exception raising (AuthError, NotFoundError, etc.)
  - connection reuse via a persistent httpx.Client
"""
import logging
from typing import Any, Optional

import httpx

from sciath_cli.config import SciathConfig, save_config

logger = logging.getLogger(__name__)

# ─── Exceptions ───────────────────────────────────────────────────────────────

class SciathAPIError(Exception):
    """Base class for all API errors."""


class AuthError(SciathAPIError):
    """401 — run sciath login."""


class ScopeError(SciathAPIError):
    """403 — API key lacks required scope."""


class NotFoundError(SciathAPIError):
    """404 — resource not found."""


class ValidationError(SciathAPIError):
    """422 — request validation failed."""
    def __init__(self, message: str, field_errors: Optional[list[Any]] = None):
        super().__init__(message)
        self.field_errors = field_errors or []


class RateLimitError(SciathAPIError):
    """429 Too Many Requests — rate limit exceeded."""
    def __init__(self, retry_after: int | None = None):
        self.retry_after = retry_after
        msg = "Rate limit exceeded."
        if retry_after:
            msg += f" Retry after {retry_after} seconds."
        super().__init__(msg)


class ServerError(SciathAPIError):
    """5xx — server-side error, eligible for retry."""
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _filename_from_headers(response: httpx.Response) -> str:
    """Extract filename from Content-Disposition header, or return a default."""
    cd = response.headers.get("content-disposition", "")
    if 'filename="' in cd:
        parts = cd.split('filename="')
        name: str = parts[1].rstrip('"')
        return name
    return "report"


# ─── Client ───────────────────────────────────────────────────────────────────

class SciathAPI:
    """
    Thin wrapper around httpx.Client.

    Request flow:
      command → method (e.g. create_scan) → _request() → httpx → exception or dict
    """

    def __init__(self, config: SciathConfig):
        self._config = config
        headers: dict[str, str] = {}
        if config.access_token:
            headers["Authorization"] = f"Bearer {config.access_token}"
        elif config.api_key:
            headers["X-API-Key"] = config.api_key
        self._client = httpx.Client(
            base_url=config.api_url,
            headers=headers,
            timeout=90.0,  # scans can take 60s+ on large SBOMs
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SciathAPI":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Internal ────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """
        Execute an HTTP request and raise typed exceptions on failure.

        Raises:
          AuthError       on 401
          ScopeError      on 403
          NotFoundError   on 404
          ValidationError on 422 (includes field_errors)
          ServerError     on 5xx (retry-eligible)
        """
        logger.debug("api.request method=%s path=%s", method, path)
        try:
            response = self._client.request(method, f"/api/{path}", **kwargs)
        except httpx.ConnectError as exc:
            raise ServerError(
                f"Cannot reach {self._config.api_url} — check your network connection "
                f"or verify the API URL with 'sciath whoami'",
                status_code=0,
            ) from exc
        except httpx.TimeoutException as exc:
            raise ServerError(
                f"Request timed out after 90s ({method} {path}) — the server may be "
                f"overloaded, or try again later",
                status_code=0,
            ) from exc

        logger.debug("api.response method=%s path=%s status=%d", method, path, response.status_code)

        if response.status_code == 401:
            # Auto-refresh OAuth2 token if we have a refresh token.
            if self._config.refresh_token and not kwargs.get("_no_refresh"):
                refreshed = self._try_refresh()
                if refreshed:
                    # Retry the original request with the new token.
                    return self._request(method, path, _no_refresh=True, **kwargs)
            raise AuthError(
                "Session expired or invalid — run [bold]sciath login[/bold] to re-authenticate"
            )
        if response.status_code == 403:
            raise ScopeError(
                "Permission denied — your API key or token lacks the required scope. "
                "Check with [bold]sciath whoami[/bold] or contact your admin"
            )
        if response.status_code == 404:
            raise NotFoundError(
                f"Resource not found ({method} {path}) — check the ID is correct"
            )
        if response.status_code == 422:
            try:
                detail = response.json().get("detail", [])
            except Exception:
                logger.debug("response.parse_error status=422 path=%s", path, exc_info=True)
                detail = []
            # Build a human-readable validation message
            if isinstance(detail, list) and detail:
                field_msgs = []
                for err in detail[:3]:
                    if isinstance(err, dict):
                        loc = " → ".join(str(part) for part in err.get("loc", []))
                        msg = err.get("msg", "invalid")
                        field_msgs.append(f"  {loc}: {msg}" if loc else f"  {msg}")
                    else:
                        field_msgs.append(f"  {err}")
                hint = "\n".join(field_msgs)
                raise ValidationError(f"Validation error:\n{hint}", field_errors=detail)
            raise ValidationError("Validation error — check your input", field_errors=detail)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(int(retry_after) if retry_after else None)
        if response.status_code >= 500:
            raise ServerError(
                f"Server error ({response.status_code}) — this is a problem on the Sciath "
                f"side, not your input. Try again in a few minutes",
                status_code=response.status_code,
            )

        result: dict[str, Any] = response.json()
        return result

    def _try_refresh(self) -> bool:
        """Attempt to refresh the OAuth2 access token. Returns True on success."""
        logger.debug("token_refresh.attempt")
        try:
            response = self._client.post(
                "/api/auth/v1/token/refresh",
                json={"refresh_token": self._config.refresh_token},
            )
            if response.status_code != 200:
                return False

            data = response.json()
            self._config.access_token = data["access_token"]
            self._config.refresh_token = data["refresh_token"]

            # Calculate expiry timestamp.
            from datetime import datetime, timedelta, timezone
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=data.get("expires_in", 3600))
            self._config.token_expires_at = expires_at.isoformat()

            # Persist updated tokens.
            save_config(self._config)

            # Update client headers for subsequent requests.
            self._client.headers["Authorization"] = f"Bearer {data['access_token']}"

            return True
        except Exception:
            logger.debug("token_refresh.failed", exc_info=True)
            return False

    # ── Auth ────────────────────────────────────────────────────────────────

    def request_device_code(self) -> dict[str, Any]:
        return self._request("POST", "auth/v1/device/code", json={"client_name": "Sciath CLI"})

    def poll_device_token(self, poll_code: str) -> dict[str, Any]:
        return self._request("GET", "auth/v1/device/token", params={"poll_code": poll_code})

    # ── Projects ────────────────────────────────────────────────────────────

    def list_projects(self, limit: int = 100) -> dict[str, Any]:
        return self._request("GET", "core/v1/projects/", params={"limit": limit})

    def create_project(self, name: str, **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name, **kwargs}
        # Omit empty values so server auto-fills (e.g. customer_id from auth)
        payload = {k: v for k, v in payload.items() if v}
        return self._request("POST", "core/v1/projects/", json=payload)

    # ── Scans ───────────────────────────────────────────────────────────────

    def resolve_scan(self, prefix: str) -> dict[str, Any]:
        """Resolve a short scan ID prefix to a full scan via server-side lookup."""
        return self._request("GET", "core/v1/scans/resolve/", params={"prefix": prefix})

    def list_scans(self, project_id: Optional[str] = None, limit: int = 100) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if project_id:
            params["project_id"] = project_id
        return self._request("GET", "core/v1/scans/", params=params)

    def create_scan(
        self,
        project_id: str,
        version_label: str,
        sbom_raw: str,
        sbom_format: str,
        kconfig_raw: str = "",
        dtb_raw: str = "",
        depgraph_raw: str = "",
        custom_filter_raw: str = "",
        policy_name: Optional[str] = None,
        yocto_machine: str = "",
        yocto_distro: str = "",
        kernel_version: str = "",
        idempotency_key: Optional[str] = None,
        extracted_packageconfigs: Optional[dict[str, list[str]]] = None,
        bsp_suppressed_cves: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        payload: dict[str, Any] = {
            "project_id": project_id,
            "version_label": version_label,
            "sbom_raw": sbom_raw,
            "sbom_format": sbom_format,
            "kconfig_raw": kconfig_raw,
        }
        if dtb_raw:
            payload["dtb_raw"] = dtb_raw
        if depgraph_raw:
            payload["depgraph_raw"] = depgraph_raw
        if policy_name:
            payload["policy_name"] = policy_name
        elif custom_filter_raw:
            payload["custom_filter_raw"] = custom_filter_raw
        if yocto_machine:
            payload["yocto_machine"] = yocto_machine
        if yocto_distro:
            payload["yocto_distro"] = yocto_distro
        if kernel_version:
            payload["kernel_version"] = kernel_version
        if extracted_packageconfigs:
            payload["extracted_packageconfigs"] = extracted_packageconfigs
        if bsp_suppressed_cves:
            payload["bsp_suppressed_cves"] = bsp_suppressed_cves

        return self._request(
            "POST", "core/v1/scans/",
            json=payload,
            headers=headers,
        )

    def trigger_analyse(self, scan_id: str) -> dict[str, Any]:
        return self._request("POST", f"scans/v1/{scan_id}/analyse/")

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        return self._request("GET", f"scans/v1/{scan_id}/status/")

    def get_cra_readiness(self, scan_id: str) -> dict[str, Any]:
        return self._request("GET", f"scans/v1/{scan_id}/cra-readiness/")

    # ── Assessments ─────────────────────────────────────────────────────────

    def list_assessments(
        self,
        scan_id: Optional[str] = None,
        status: Optional[str] = None,
        filter_layer: Optional[str] = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if scan_id:
            params["scan_id"] = scan_id
        if status:
            params["status"] = status
        if filter_layer:
            params["filter_layer"] = filter_layer
        return self._request("GET", "assessments/v1/assessments/", params=params)

    def update_assessment(self, assessment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PATCH", f"assessments/v1/assessments/{assessment_id}/",
            json=payload,
        )

    # ── Reports ─────────────────────────────────────────────────────────────

    def generate_report(self, scan_id: str, fmt: str) -> dict[str, Any]:
        """POST /reports/v1/scans/{scan_id}/generate/ → report metadata dict."""
        return self._request("POST", f"reports/v1/scans/{scan_id}/generate/", json={"format": fmt})

    def get_report(self, report_id: str) -> dict[str, Any]:
        """GET /reports/v1/{report_id}/ → report metadata + status."""
        return self._request("GET", f"reports/v1/{report_id}/")

    def download_report(self, report_id: str) -> tuple[bytes, str]:
        """
        GET /reports/v1/{report_id}/download/ → (content_bytes, filename).

        Two server modes:
        - S3 prod: JSON {"url": "<presigned>", "filename": "..."} → fetch from S3
        - Local dev: raw bytes with Content-Disposition header
        """
        response = self._client.request(
            "GET", f"/api/reports/v1/{report_id}/download/",
            timeout=120.0,
        )
        if response.status_code == 404:
            raise NotFoundError("Report not found")
        if response.status_code == 202:
            raise SciathAPIError("Report is still generating")
        if response.status_code == 409:
            raise SciathAPIError("Report generation failed")
        if response.status_code >= 400:
            raise ServerError(
                f"Download failed ({response.status_code})",
                status_code=response.status_code,
            )

        content_type = response.headers.get("content-type", "")

        # S3 mode: server returns JSON with presigned URL
        if "application/json" in content_type:
            try:
                meta = response.json()
            except Exception:
                # JSON format report returned inline (VEX, CSAF)
                if not response.content:
                    raise SciathAPIError("Server returned empty file")
                return response.content, _filename_from_headers(response)
            if "url" in meta:
                content = self._download_from_url(meta["url"])
                return content, meta.get("filename", "report")
            # JSON report content returned inline
            if not response.content:
                raise SciathAPIError("Server returned empty file")
            return response.content, _filename_from_headers(response)

        # Disk mode: raw bytes streamed directly
        if not response.content:
            raise SciathAPIError("Server returned empty file")
        return response.content, _filename_from_headers(response)

    def download_evidence_pack(self, scan_id: str) -> tuple[bytes, str]:
        """GET /reports/v1/scans/{scan_id}/evidence-pack/ → (zip_bytes, filename)."""
        response = self._client.request(
            "GET", f"/api/reports/v1/scans/{scan_id}/evidence-pack/",
            timeout=120.0,
        )
        if response.status_code == 404:
            raise NotFoundError("Scan not found")
        if response.status_code >= 400:
            raise ServerError(
                f"Evidence pack download failed ({response.status_code})",
                status_code=response.status_code,
            )
        if not response.content:
            raise SciathAPIError("Server returned empty evidence pack")
        return response.content, _filename_from_headers(response)

    def export_cdx(self, scan_id: str, fmt: str = "vex_cdx", validate: bool = False) -> bytes:
        """
        GET /reports/v1/scans/{scan_id}/export/ → raw CycloneDX JSON bytes.
        Uses a raw httpx request (not _request) to return bytes, not JSON.
        """
        response = self._client.request(
            "GET", f"/api/reports/v1/scans/{scan_id}/export/",
            params={"format": fmt, "check_schema": str(validate).lower()},
        )
        if response.status_code == 404:
            raise NotFoundError("Scan not found")
        if response.status_code == 422:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                logger.debug("export.parse_error scan_id=%s", scan_id, exc_info=True)
                detail = response.text
            raise ValidationError(str(detail))
        if response.status_code >= 400:
            raise ServerError(f"Export failed ({response.status_code})", status_code=response.status_code)
        return response.content

    # ── Policies ──────────────────────────────────────────────────────────

    def list_policies(self, search: Optional[str] = None, limit: int = 100) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if search:
            params["search"] = search
        return self._request("GET", "policies/v1/filter-policies/", params=params)

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        return self._request("GET", f"policies/v1/filter-policies/{policy_id}/")

    def create_policy(self, name: str, content: dict[str, Any], description: str = "") -> dict[str, Any]:
        return self._request(
            "POST", "policies/v1/filter-policies/",
            json={"name": name, "description": description, "content_raw": content},
        )

    def update_policy(self, policy_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PUT", f"policies/v1/filter-policies/{policy_id}/",
            json=payload,
        )

    def delete_policy(self, policy_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"policies/v1/filter-policies/{policy_id}/")

    def policy_history(self, policy_id: str, limit: int = 50) -> dict[str, Any]:
        return self._request(
            "GET", f"policies/v1/filter-policies/{policy_id}/history/",
            params={"limit": limit},
        )

    def import_vex_policy(
        self, name: str, vex_content: dict[str, Any], description: str = "", trust_vendor: bool = False,
    ) -> dict[str, Any]:
        return self._request(
            "POST", "policies/v1/filter-policies/from-vex/",
            json={
                "name": name,
                "description": description,
                "vex_content": vex_content,
                "trust_vendor": trust_vendor,
            },
        )

    # ── Downloads ─────────────────────────────────────────────────────────

    def _download_from_url(self, url: str) -> bytes:
        """
        Fetch bytes from a presigned S3 URL.
        Uses a fresh httpx client — does NOT send X-API-Key to S3.
        """
        import httpx as _httpx
        try:
            response = _httpx.get(url, follow_redirects=True, timeout=120.0)
        except _httpx.TimeoutException as exc:
            raise ServerError(
                "Report download timed out — the file may be large, try again",
                status_code=0,
            ) from exc
        except _httpx.ConnectError as exc:
            raise ServerError(
                "Cannot reach download server — check your network connection",
                status_code=0,
            ) from exc
        if response.status_code >= 400:
            raise ServerError(
                f"Download failed (HTTP {response.status_code}) — the download link may "
                f"have expired, regenerate the report",
                status_code=response.status_code,
            )
        if not response.content:
            raise SciathAPIError("Server returned empty file")
        return response.content
