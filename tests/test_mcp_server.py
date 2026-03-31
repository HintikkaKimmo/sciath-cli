"""
Unit tests for the MCP server tool functions.

Tests the raw async tool functions directly, mocking _get_api() to avoid
real API calls. Uses pytest-asyncio for async test execution.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from sciath_cli.mcp_server import (
    _tool_get_compliance_status,
    _tool_get_scan_status,
    _tool_list_findings,
    _tool_scan_sbom,
    call_tool,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_api(monkeypatch):
    """Patch _get_api to return a MagicMock with common API methods."""
    api = MagicMock()
    api.close = MagicMock()
    monkeypatch.setattr("sciath_cli.mcp_server._get_api", lambda: api)
    return api


# ---------------------------------------------------------------------------
# TestGetApi — tests _get_api itself (monkeypatches load_config)
# ---------------------------------------------------------------------------

class TestGetApi:
    def test_happy_path(self, monkeypatch):
        """Config with api_key returns a SciathAPI instance."""
        from sciath_cli.config import SciathConfig
        from sciath_cli.mcp_server import _get_api

        cfg = SciathConfig(api_url="https://example.com", api_key="test-key-123")
        monkeypatch.setattr("sciath_cli.mcp_server.load_config", lambda: cfg)

        # Patch SciathAPI so we don't need a real httpx client
        mock_cls = MagicMock()
        monkeypatch.setattr("sciath_cli.mcp_server.SciathAPI", mock_cls)

        result = _get_api()
        mock_cls.assert_called_once_with(cfg)
        assert result == mock_cls.return_value

    def test_no_api_key_raises(self, monkeypatch):
        """Missing api_key raises ValueError."""
        from sciath_cli.config import SciathConfig
        from sciath_cli.mcp_server import _get_api

        cfg = SciathConfig(api_url="https://example.com", api_key="")
        monkeypatch.setattr("sciath_cli.mcp_server.load_config", lambda: cfg)

        with pytest.raises(ValueError, match="Not authenticated"):
            _get_api()


# ---------------------------------------------------------------------------
# TestScanSbom
# ---------------------------------------------------------------------------

class TestScanSbom:
    @pytest.mark.asyncio
    async def test_happy_path(self, mock_api, tmp_path):
        """SBOM file exists, scan completes within polling loop."""
        sbom_file = tmp_path / "firmware.cdx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        mock_api.create_scan.return_value = {"id": "scan-abc"}
        mock_api.get_scan_status.return_value = {
            "status": "triage",
            "total_components": 42,
            "total_vulnerabilities": 10,
            "suppressed_count": 7,
        }

        with patch("time.sleep"):
            result = await _tool_scan_sbom({
                "sbom_path": str(sbom_file),
                "project_id": "proj-1",
            })

        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data["scan_id"] == "scan-abc"
        assert data["status"] == "triage"
        assert data["remaining"] == 3
        mock_api.create_scan.assert_called_once()
        mock_api.trigger_analyse.assert_called_once_with("scan-abc")
        mock_api.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_sbom_file_not_found(self, mock_api):
        """Non-existent SBOM path returns error text."""
        result = await _tool_scan_sbom({
            "sbom_path": "/nonexistent/firmware.json",
            "project_id": "proj-1",
        })

        assert len(result) == 1
        assert "not found" in result[0].text
        mock_api.create_scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_with_kconfig(self, mock_api, tmp_path):
        """Optional kconfig_path is read and passed along."""
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')
        kconfig_file = tmp_path / ".config"
        kconfig_file.write_text("CONFIG_BT=n\nCONFIG_WLAN=n\n")

        mock_api.create_scan.return_value = {"id": "scan-k"}
        mock_api.get_scan_status.return_value = {"status": "complete"}

        with patch("time.sleep"):
            await _tool_scan_sbom({
                "sbom_path": str(sbom_file),
                "project_id": "proj-1",
                "kconfig_path": str(kconfig_file),
            })

        # Verify kconfig_raw was passed to create_scan
        call_kwargs = mock_api.create_scan.call_args
        assert "CONFIG_BT=n" in call_kwargs.kwargs.get("kconfig_raw", call_kwargs[1].get("kconfig_raw", ""))

    @pytest.mark.asyncio
    async def test_timeout_still_analysing(self, mock_api, tmp_path):
        """Scan never reaches terminal state within polling loop."""
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        mock_api.create_scan.return_value = {"id": "scan-slow"}
        mock_api.get_scan_status.return_value = {"status": "analysing"}

        with patch("time.sleep"):
            result = await _tool_scan_sbom({
                "sbom_path": str(sbom_file),
                "project_id": "proj-1",
            })

        assert "still analysing" in result[0].text
        # Should have polled 24 times
        assert mock_api.get_scan_status.call_count == 24
        mock_api.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestGetScanStatus
# ---------------------------------------------------------------------------

class TestGetScanStatus:
    @pytest.mark.asyncio
    async def test_happy_path(self, mock_api):
        """Returns JSON of scan status."""
        mock_api.get_scan_status.return_value = {
            "id": "scan-123",
            "status": "triage",
            "total_components": 50,
        }

        result = await _tool_get_scan_status({"scan_id": "scan-123"})

        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data["status"] == "triage"
        assert data["id"] == "scan-123"
        mock_api.get_scan_status.assert_called_once_with("scan-123")
        mock_api.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestListFindings
# ---------------------------------------------------------------------------

class TestListFindings:
    @pytest.mark.asyncio
    async def test_happy_path(self, mock_api):
        """Returns formatted findings list."""
        mock_api.list_assessments.return_value = {
            "items": [
                {
                    "vulnerability": {
                        "vuln_id": "CVE-2024-1234",
                        "cvss_score": 9.8,
                        "is_kev": True,
                        "component": {"name": "openssl"},
                    },
                    "status": "affected",
                    "filter_layer": "none",
                    "justification_text": "",
                },
                {
                    "vulnerability": {
                        "vuln_id": "CVE-2024-5678",
                        "cvss_score": 4.3,
                        "is_kev": False,
                        "component": {"name": "busybox"},
                    },
                    "status": "not_affected",
                    "filter_layer": "kconfig",
                    "justification_text": "CONFIG_BT=n",
                },
            ],
        }

        result = await _tool_list_findings({"scan_id": "scan-abc"})

        data = json.loads(result[0].text)
        assert data["total"] == 2
        assert data["findings"][0]["cve_id"] == "CVE-2024-1234"
        assert data["findings"][0]["is_kev"] is True
        assert data["findings"][1]["filter_layer"] == "kconfig"
        mock_api.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_with_status_filter(self, mock_api):
        """Status filter is passed through to API call."""
        mock_api.list_assessments.return_value = {"items": []}

        await _tool_list_findings({
            "scan_id": "scan-abc",
            "status": "affected",
        })

        call_kwargs = mock_api.list_assessments.call_args
        assert call_kwargs.kwargs.get("status", call_kwargs[1].get("status")) == "affected"


# ---------------------------------------------------------------------------
# TestGetComplianceStatus
# ---------------------------------------------------------------------------

class TestGetComplianceStatus:
    @pytest.mark.asyncio
    async def test_happy_path(self, mock_api):
        """Returns compliance summary from latest scan."""
        mock_api.list_scans.return_value = {
            "items": [
                {
                    "version_label": "v1.2.0",
                    "status": "triage",
                    "total_vulnerabilities": 20,
                    "suppressed_count": 15,
                },
            ],
        }

        result = await _tool_get_compliance_status({"project_id": "proj-1"})

        data = json.loads(result[0].text)
        assert data["project_id"] == "proj-1"
        assert data["total_cves"] == 20
        assert data["remaining"] == 5
        assert data["noise_reduction_pct"] == 75
        mock_api.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_scans(self, mock_api):
        """Project with no scans returns no_scans status."""
        mock_api.list_scans.return_value = {"items": []}

        result = await _tool_get_compliance_status({"project_id": "proj-empty"})

        data = json.loads(result[0].text)
        assert data["status"] == "no_scans"
        mock_api.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestCallToolDispatch
# ---------------------------------------------------------------------------

class TestCallToolDispatch:
    @pytest.mark.asyncio
    async def test_unknown_tool(self, mock_api):
        """Unknown tool name returns error message."""
        result = await call_tool("nonexistent_tool", {})

        assert len(result) == 1
        assert "Unknown tool: nonexistent_tool" in result[0].text
