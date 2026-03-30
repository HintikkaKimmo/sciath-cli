"""
Tests for the report download flow and related fixes.

Covers:
- BUG-001: download_report() handles both presigned URL and streaming responses
- BUG-002: report command resolves short scan ID prefixes
- Empty response guard
- 202 (still generating) handling
"""
import json

import httpx
import pytest

from sciath_cli.api import NotFoundError, SciathAPI, SciathAPIError
from sciath_cli.config import SciathConfig


def _api_with_handler(handler) -> SciathAPI:
    """Build a SciathAPI with a custom mock transport handler."""
    config = SciathConfig(api_url="https://test.sciath.io", api_key="sk_test")
    api = SciathAPI(config)
    api._client = httpx.Client(
        base_url="https://test.sciath.io",
        transport=httpx.MockTransport(handler),
    )
    return api


# ─── download_report() ───────────────────────────────────────────────────────


class TestDownloadReport:
    def test_presigned_url_fetches_from_s3(self, monkeypatch):
        """S3 mode: server returns JSON with presigned URL, CLI fetches from it."""
        pdf_bytes = b"%PDF-1.7 fake pdf content"
        meta = {"url": "https://bucket.s3.fr-par.scw.cloud/report.pdf", "expires_in": 900, "filename": "report.pdf"}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=json.dumps(meta).encode(), headers={"Content-Type": "application/json"})

        api = _api_with_handler(handler)

        # Mock the S3 download
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI._download_from_url",
            lambda self, url: pdf_bytes,
        )
        content, filename = api.download_report("report-123")
        assert content == pdf_bytes
        assert filename == "report.pdf"

    def test_streaming_returns_raw_bytes(self):
        """Disk mode: server streams PDF bytes with Content-Disposition."""
        pdf_bytes = b"%PDF-1.7 fake pdf content"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=pdf_bytes,
                headers={
                    "Content-Type": "application/pdf",
                    "Content-Disposition": 'attachment; filename="sciath_article13_v1.pdf"',
                },
            )

        api = _api_with_handler(handler)
        content, filename = api.download_report("report-123")
        assert content == pdf_bytes
        assert filename == "sciath_article13_v1.pdf"

    def test_json_report_inline(self):
        """JSON format (VEX/CSAF): returned inline as JSON bytes."""
        vex = {"bomFormat": "CycloneDX", "vulnerabilities": []}
        vex_bytes = json.dumps(vex).encode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=vex_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Content-Disposition": 'attachment; filename="sciath_vex_cdx_v1.json"',
                },
            )

        api = _api_with_handler(handler)
        content, filename = api.download_report("report-123")
        assert json.loads(content)["bomFormat"] == "CycloneDX"
        assert filename == "sciath_vex_cdx_v1.json"

    def test_404_raises_not_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        api = _api_with_handler(handler)
        with pytest.raises(NotFoundError):
            api.download_report("nonexistent")

    def test_202_raises_still_generating(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.dumps({"status": "generating", "retry_after": 3}).encode()
            return httpx.Response(202, content=body, headers={"Content-Type": "application/json"})

        api = _api_with_handler(handler)
        with pytest.raises(SciathAPIError, match="still generating"):
            api.download_report("report-123")

    def test_empty_body_raises_error(self):
        """Zero-byte response should raise an error, not write an empty file."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"", headers={"Content-Type": "application/pdf"})

        api = _api_with_handler(handler)
        with pytest.raises(SciathAPIError, match="empty file"):
            api.download_report("report-123")

    def test_409_raises_generation_failed(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(409)

        api = _api_with_handler(handler)
        with pytest.raises(SciathAPIError, match="failed"):
            api.download_report("report-123")


# ─── Cache version key ───────────────────────────────────────────────────────


class TestCacheVersionKey:
    def test_different_version_different_key(self):
        from sciath_cli.cache import _cache_key

        key_v1 = _cache_key("proj", "v1", "sbom", "", "")
        key_v2 = _cache_key("proj", "v2", "sbom", "", "")
        assert key_v1 != key_v2

    def test_same_version_same_key(self):
        from sciath_cli.cache import _cache_key

        key1 = _cache_key("proj", "v1", "sbom", "", "")
        key2 = _cache_key("proj", "v1", "sbom", "", "")
        assert key1 == key2
