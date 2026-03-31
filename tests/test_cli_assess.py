"""
Integration tests for assessment commands via CliRunner + mock API.
"""
import json

import pytest
from typer.testing import CliRunner

from sciath_cli.config import SciathConfig, save_config
from sciath_cli.main import app

runner = CliRunner()


@pytest.fixture
def authed_config():
    save_config(SciathConfig(
        api_key="sk_test",
        user_email="kim@acme.com",
        customer_name="Acme Corp",
    ))


SAMPLE_ASSESSMENT = {
    "id": "aaaabbbb-1111-2222-3333-444455556666",
    "status": "under_investigation",
    "filter_layer": "kconfig",
    "confidence": 0.95,
    "vulnerability": {
        "vuln_id": "CVE-2026-1234",
        "cvss_score": 7.5,
        "epss_score": 0.42,
        "confidence_tier": "HIGH",
    },
}


class TestListAssessments:
    def test_happy_path_table(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_assessments",
            lambda self, **kw: {"items": [SAMPLE_ASSESSMENT], "total": 1},
        )

        result = runner.invoke(app, ["assess", "list"])
        assert result.exit_code == 0, result.output
        assert "CVE-2026-1234" in result.output
        assert "7.5" in result.output
        assert "kconfig" in result.output
        assert "1 assessment(s)" in result.output

    def test_empty_result(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_assessments",
            lambda self, **kw: {"items": [], "total": 0},
        )

        result = runner.invoke(app, ["assess", "list"])
        assert result.exit_code == 0, result.output
        assert "No assessments found" in result.output

    def test_json_format(self, authed_config, monkeypatch):
        payload = {"items": [SAMPLE_ASSESSMENT], "total": 1}
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_assessments",
            lambda self, **kw: payload,
        )

        result = runner.invoke(app, ["assess", "list", "--format", "json"])
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["total"] == 1
        assert parsed["items"][0]["id"] == SAMPLE_ASSESSMENT["id"]

    def test_with_scan_id(self, authed_config, monkeypatch):
        resolved_id = "full-uuid-1234-5678-abcd-ef0123456789"
        monkeypatch.setattr(
            "sciath_cli.commands.assess._resolve_scan_id",
            lambda api, sid: resolved_id,
        )
        captured_kwargs = {}
        def mock_list(self, **kw):
            captured_kwargs.update(kw)
            return {"items": [], "total": 0}
        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_assessments", mock_list)

        result = runner.invoke(app, ["assess", "list", "abc123"])
        assert result.exit_code == 0, result.output
        assert captured_kwargs["scan_id"] == resolved_id

    def test_pending_flag(self, authed_config, monkeypatch):
        captured_kwargs = {}
        def mock_list(self, **kw):
            captured_kwargs.update(kw)
            return {"items": [], "total": 0}
        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_assessments", mock_list)

        result = runner.invoke(app, ["assess", "list", "--pending"])
        assert result.exit_code == 0, result.output
        assert captured_kwargs["status"] == "under_investigation"

    def test_api_error_exits_1(self, authed_config, monkeypatch):
        from sciath_cli.api import SciathAPIError

        def mock_list(self, **kw):
            raise SciathAPIError("Connection refused")
        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_assessments", mock_list)

        result = runner.invoke(app, ["assess", "list"])
        assert result.exit_code == 1
        assert "Connection refused" in result.output


class TestApprove:
    def test_happy_path(self, authed_config, monkeypatch):
        captured = {}
        def mock_update(self, aid, payload):
            captured["aid"] = aid
            captured["payload"] = payload
            return {"id": aid, "review_status": "approved"}
        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_assessment", mock_update)

        result = runner.invoke(app, ["assess", "approve", "abc12345"])
        assert result.exit_code == 0, result.output
        assert "approved" in result.output
        assert captured["payload"]["review_status"] == "approved"
        assert captured["payload"]["review_note"] == ""

    def test_with_note(self, authed_config, monkeypatch):
        captured = {}
        def mock_update(self, aid, payload):
            captured["payload"] = payload
            return {"id": aid, "review_status": "approved"}
        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_assessment", mock_update)

        result = runner.invoke(app, ["assess", "approve", "abc12345", "--note", "Reviewed by Kim"])
        assert result.exit_code == 0, result.output
        assert captured["payload"]["review_note"] == "Reviewed by Kim"

    def test_api_error_exits_1(self, authed_config, monkeypatch):
        from sciath_cli.api import SciathAPIError

        def mock_update(self, aid, payload):
            raise SciathAPIError("Not found")
        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_assessment", mock_update)

        result = runner.invoke(app, ["assess", "approve", "abc12345"])
        assert result.exit_code == 1
        assert "Not found" in result.output


class TestReject:
    def test_happy_path(self, authed_config, monkeypatch):
        captured = {}
        def mock_update(self, aid, payload):
            captured["payload"] = payload
            return {"id": aid, "review_status": "rejected"}
        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_assessment", mock_update)

        result = runner.invoke(app, ["assess", "reject", "xyz98765"])
        assert result.exit_code == 0, result.output
        assert "flagged for review" in result.output
        assert captured["payload"]["review_status"] == "rejected"

    def test_api_error_exits_1(self, authed_config, monkeypatch):
        from sciath_cli.api import SciathAPIError

        def mock_update(self, aid, payload):
            raise SciathAPIError("Server error")
        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_assessment", mock_update)

        result = runner.invoke(app, ["assess", "reject", "xyz98765"])
        assert result.exit_code == 1
        assert "Server error" in result.output
