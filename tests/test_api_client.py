"""
Unit tests for SciathAPI._request() error handling.

Uses httpx.MockTransport to simulate backend responses without a real server.
"""
import httpx
import pytest
from sciath_cli.api import (
    AuthError,
    NotFoundError,
    SciathAPI,
    ScopeError,
    ServerError,
    ValidationError,
)
from sciath_cli.config import SciathConfig


def _api_with_response(status_code: int, body: dict | str = "") -> SciathAPI:
    """Build a SciathAPI instance backed by a mock transport."""
    if isinstance(body, dict):
        import json
        content = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
    else:
        content = body.encode() if isinstance(body, str) else body
        headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=content, headers=headers)

    config = SciathConfig(api_url="https://test.sciath.io", api_key="sk_test")
    api = SciathAPI(config)
    api._client = httpx.Client(
        base_url="https://test.sciath.io",
        transport=httpx.MockTransport(handler),
    )
    return api


class TestRequestErrorHandling:
    def test_200_returns_json(self):
        api = _api_with_response(200, {"items": [], "total": 0})
        result = api._request("GET", "core/v1/projects/")
        assert result["total"] == 0

    def test_401_raises_auth_error(self):
        api = _api_with_response(401, {"detail": "Unauthorized"})
        with pytest.raises(AuthError):
            api._request("GET", "core/v1/projects/")

    def test_403_raises_scope_error(self):
        api = _api_with_response(403, {"detail": "Missing scope"})
        with pytest.raises(ScopeError):
            api._request("GET", "core/v1/projects/")

    def test_404_raises_not_found_error(self):
        api = _api_with_response(404, {"detail": "Not found"})
        with pytest.raises(NotFoundError):
            api._request("GET", "core/v1/scans/bad-id/status/")

    def test_422_raises_validation_error_with_field_errors(self):
        body = {"detail": [{"loc": ["body", "sbom_raw"], "msg": "field required"}]}
        api = _api_with_response(422, body)
        with pytest.raises(ValidationError) as exc_info:
            api._request("POST", "core/v1/scans/")
        assert len(exc_info.value.field_errors) == 1

    def test_500_raises_server_error(self):
        api = _api_with_response(500, {"detail": "Internal server error"})
        with pytest.raises(ServerError) as exc_info:
            api._request("POST", "scans/v1/abc/analyse/")
        assert exc_info.value.status_code == 500

    def test_503_raises_server_error(self):
        api = _api_with_response(503, "Service unavailable")
        with pytest.raises(ServerError):
            api._request("GET", "scans/v1/abc/status/")

    def test_connection_error_raises_server_error(self):
        def failing_handler(request):
            raise httpx.ConnectError("Connection refused")

        config = SciathConfig(api_url="https://test.sciath.io", api_key="sk_test")
        api = SciathAPI(config)
        api._client = httpx.Client(
            base_url="https://test.sciath.io",
            transport=httpx.MockTransport(failing_handler),
        )
        with pytest.raises(ServerError):
            api._request("GET", "core/v1/projects/")
