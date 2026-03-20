"""
HTTP client for the Sciath API.

All requests go through _request() which centralises:
  - auth header injection
  - typed exception raising (AuthError, NotFoundError, etc.)
  - connection reuse via a persistent httpx.Client
"""
from typing import Any, Optional

import httpx

from sciath_cli.config import SciathConfig

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
    def __init__(self, message: str, field_errors: Optional[list] = None):
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
        self._client = httpx.Client(
            base_url=config.api_url,
            headers={"X-API-Key": config.api_key or ""},
            timeout=90.0,  # scans can take 60s+ on large SBOMs
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── Internal ────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """
        Execute an HTTP request and raise typed exceptions on failure.

        Raises:
          AuthError       on 401
          ScopeError      on 403
          NotFoundError   on 404
          ValidationError on 422 (includes field_errors)
          ServerError     on 5xx (retry-eligible)
        """
        try:
            response = self._client.request(method, f"/api/{path}", **kwargs)
        except httpx.ConnectError as exc:
            raise ServerError(f"Connection failed: {exc}", status_code=0) from exc
        except httpx.TimeoutException as exc:
            raise ServerError(f"Request timed out: {exc}", status_code=0) from exc

        if response.status_code == 401:
            raise AuthError("Not authenticated — run [bold]sciath login[/bold]")
        if response.status_code == 403:
            raise ScopeError("Permission denied (missing API key scope)")
        if response.status_code == 404:
            raise NotFoundError("Resource not found")
        if response.status_code == 422:
            try:
                detail = response.json().get("detail", [])
            except Exception:
                detail = []
            raise ValidationError("Validation error", field_errors=detail)
        if response.status_code >= 500:
            raise ServerError(
                f"Server error ({response.status_code})", status_code=response.status_code
            )

        return response.json()

    # ── Auth ────────────────────────────────────────────────────────────────

    def request_device_code(self) -> dict:
        return self._request("POST", "auth/v1/device/code", json={"client_name": "Sciath CLI"})

    def poll_device_token(self, poll_code: str) -> dict:
        return self._request("GET", "auth/v1/device/token", params={"poll_code": poll_code})

    # ── Projects ────────────────────────────────────────────────────────────

    def list_projects(self, limit: int = 100) -> dict:
        return self._request("GET", "core/v1/projects/", params={"limit": limit})

    def create_project(self, customer_id: str, name: str, **kwargs) -> dict:
        return self._request(
            "POST", "core/v1/projects/",
            json={"customer_id": customer_id, "name": name, **kwargs},
        )

    # ── Scans ───────────────────────────────────────────────────────────────

    def list_scans(self, project_id: Optional[str] = None, limit: int = 20) -> dict:
        params: dict = {"limit": limit}
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
        idempotency_key: Optional[str] = None,
    ) -> dict:
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        return self._request(
            "POST", "core/v1/scans/",
            json={
                "project_id": project_id,
                "version_label": version_label,
                "sbom_raw": sbom_raw,
                "sbom_format": sbom_format,
                "kconfig_raw": kconfig_raw,
            },
            headers=headers,
        )

    def trigger_analyse(self, scan_id: str) -> dict:
        return self._request("POST", f"scans/v1/{scan_id}/analyse/")

    def get_scan_status(self, scan_id: str) -> dict:
        return self._request("GET", f"scans/v1/{scan_id}/status/")

    # ── Assessments ─────────────────────────────────────────────────────────

    def list_assessments(
        self,
        scan_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        params: dict = {"limit": limit}
        if scan_id:
            params["scan_id"] = scan_id
        if status:
            params["status"] = status
        return self._request("GET", "assessments/v1/assessments/", params=params)

    def update_assessment(self, assessment_id: str, payload: dict) -> dict:
        return self._request(
            "PATCH", f"assessments/v1/assessments/{assessment_id}/",
            json=payload,
        )

    # ── Reports ─────────────────────────────────────────────────────────────

    def generate_report(self, scan_id: str, fmt: str) -> dict:
        """POST /reports/v1/scans/{scan_id}/generate/ → report metadata dict."""
        return self._request("POST", f"reports/v1/scans/{scan_id}/generate/", json={"format": fmt})

    def get_report(self, report_id: str) -> dict:
        """GET /reports/v1/{report_id}/ → report metadata + status."""
        return self._request("GET", f"reports/v1/{report_id}/")

    def get_report_download_url(self, report_id: str) -> dict:
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
            params={"format": fmt, "validate": str(validate).lower()},
        )
        if response.status_code == 404:
            raise NotFoundError("Scan not found")
        if response.status_code == 422:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise ValidationError(str(detail))
        if response.status_code >= 400:
            raise ServerError(f"Export failed ({response.status_code})", status_code=response.status_code)
        return response.content

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
