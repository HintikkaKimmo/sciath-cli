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


class ServerError(SciathAPIError):
    """5xx — server-side error, eligible for retry."""
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


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
            raise ServerError(f"Connection failed: {exc}", status_code=0) from exc
        except httpx.TimeoutException as exc:
            raise ServerError(f"Request timed out: {exc}", status_code=0) from exc

        logger.debug("api.response method=%s path=%s status=%d", method, path, response.status_code)

        if response.status_code == 401:
            # Auto-refresh OAuth2 token if we have a refresh token.
            if self._config.refresh_token and not kwargs.get("_no_refresh"):
                refreshed = self._try_refresh()
                if refreshed:
                    # Retry the original request with the new token.
                    return self._request(method, path, _no_refresh=True, **kwargs)
            raise AuthError("Not authenticated — run [bold]sciath login[/bold]")
        if response.status_code == 403:
            raise ScopeError("Permission denied (missing API key scope)")
        if response.status_code == 404:
            raise NotFoundError("Resource not found")
        if response.status_code == 422:
            try:
                detail = response.json().get("detail", [])
            except Exception:
                logger.debug("response.parse_error status=422 path=%s", path, exc_info=True)
                detail = []
            raise ValidationError("Validation error", field_errors=detail)
        if response.status_code >= 500:
            raise ServerError(
                f"Server error ({response.status_code})", status_code=response.status_code
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

    def list_scans(self, project_id: Optional[str] = None, limit: int = 20) -> dict[str, Any]:
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

        return self._request(
            "POST", "core/v1/scans/",
            json=payload,
            headers=headers,
        )

    def trigger_analyse(self, scan_id: str) -> dict[str, Any]:
        return self._request("POST", f"scans/v1/{scan_id}/analyse/")

    def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        return self._request("GET", f"scans/v1/{scan_id}/status/")

    # ── Assessments ─────────────────────────────────────────────────────────

    def list_assessments(
        self,
        scan_id: Optional[str] = None,
        status: Optional[str] = None,
        filter_layer: Optional[str] = None,
        limit: int = 50,
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

    def get_report_download_url(self, report_id: str) -> dict[str, Any]:
        """
        GET /reports/v1/{report_id}/download/ → {"url": "...", "expires_in": 900}
        Returns the JSON metadata dict; caller fetches the URL separately.
        """
        return self._request("GET", f"reports/v1/{report_id}/download/")

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

    def _download(self, url: str) -> bytes:
        """
        Fetch bytes from a presigned URL (Scaleway S3 or local).
        Uses a fresh httpx client — does NOT send X-API-Key to S3.
        """
        import httpx as _httpx
        try:
            response = _httpx.get(url, follow_redirects=True, timeout=120.0)
        except _httpx.TimeoutException as exc:
            raise ServerError(f"Download timed out: {exc}", status_code=0) from exc
        except _httpx.ConnectError as exc:
            raise ServerError(f"Download connection failed: {exc}", status_code=0) from exc
        if response.status_code >= 400:
            raise ServerError(f"Download failed ({response.status_code})", status_code=response.status_code)
        return response.content
