"""
Integration tests for policy commands via CliRunner + mock API.
"""

import json

import pytest
from typer.testing import CliRunner

from sciath_cli.api import SciathAPIError
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


SAMPLE_POLICY = {
    "id": "pol-uuid-1234",
    "name": "baseline",
    "version": 2,
    "description": "Baseline filter policy",
    "rule_count": 3,
    "content_hash": "abc123def456789",
    "created_at": "2026-03-01T10:00:00Z",
    "updated_at": "2026-03-15T12:00:00Z",
    "content_raw": {
        "version": "1",
        "rules": [
            {
                "id": "rule-1",
                "match": {"type": "exact_cve", "value": "CVE-2024-1234"},
                "result": {"status": "not_affected", "confidence": "HIGH"},
            },
            {
                "id": "rule-2",
                "match": {"type": "cpe_pattern", "value": "cpe:2.3:a:openssl:*"},
                "result": {"status": "not_affected", "confidence": "MEDIUM"},
            },
            {
                "id": "rule-3",
                "match": {"type": "keyword", "value": "bluetooth"},
                "result": {"status": "not_affected", "confidence": "LOW"},
            },
        ],
    },
}

SAMPLE_POLICY_B = {
    "id": "pol-uuid-5678",
    "name": "vendor-vex",
    "version": 1,
    "description": "Vendor VEX import",
    "rule_count": 2,
    "content_hash": "xyz789abc123456",
    "created_at": "2026-03-10T08:00:00Z",
    "updated_at": "2026-03-10T08:00:00Z",
    "content_raw": {
        "version": "1",
        "rules": [
            {
                "id": "rule-3",
                "match": {"type": "exact_cve", "value": "CVE-2024-5678"},
                "result": {"status": "not_affected", "confidence": "HIGH"},
            },
            {
                "id": "rule-4",
                "match": {"type": "cwe", "value": "CWE-79"},
                "result": {"status": "not_affected", "confidence": "MEDIUM"},
            },
        ],
    },
}


def _make_json_file(tmp_path, name="policy.json", content=None):
    """Create a JSON file in tmp_path and return the path."""
    if content is None:
        content = {"version": "1", "rules": [{"id": "r1", "match": {"type": "exact_cve", "value": "CVE-2024-0001"}, "result": {"status": "not_affected", "confidence": "HIGH"}}]}
    f = tmp_path / name
    f.write_text(json.dumps(content))
    return f


class TestListPolicies:
    def test_happy_path(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY, SAMPLE_POLICY_B]},
        )
        result = runner.invoke(app, ["policy", "list"])
        assert result.exit_code == 0, result.output
        assert "baseline" in result.output
        assert "vendor-vex" in result.output
        assert "v2" in result.output

    def test_with_search(self, authed_config, monkeypatch):
        calls = []

        def mock_list(self, **kw):
            calls.append(kw)
            return {"items": [SAMPLE_POLICY]}

        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_policies", mock_list)
        result = runner.invoke(app, ["policy", "list", "--search", "base"])
        assert result.exit_code == 0, result.output
        assert calls[0]["search"] == "base"

    def test_empty(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["policy", "list"])
        assert result.exit_code == 0
        assert "No policies found" in result.output

    def test_api_error(self, authed_config, monkeypatch):
        def raise_err(self, **kw):
            raise SciathAPIError("connection refused")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_policies", raise_err)
        result = runner.invoke(app, ["policy", "list"])
        assert result.exit_code == 1
        assert "connection refused" in result.output

    def test_no_auth_exits(self):
        result = runner.invoke(app, ["policy", "list"])
        assert result.exit_code == 1


class TestShowPolicy:
    def test_happy_path(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "show", "baseline"])
        assert result.exit_code == 0, result.output
        assert "baseline" in result.output
        assert "v2" in result.output
        assert "rule-1" in result.output
        assert "exact_cve" in result.output

    def test_case_insensitive_match(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "show", "BASELINE"])
        assert result.exit_code == 0, result.output
        assert "baseline" in result.output

    def test_match_by_id_prefix(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "show", "pol-uuid"])
        assert result.exit_code == 0, result.output
        assert "baseline" in result.output

    def test_not_found(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["policy", "show", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_no_rules(self, authed_config, monkeypatch):
        no_rules = {**SAMPLE_POLICY, "content_raw": {"version": "1", "rules": []}, "rule_count": 0}
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [no_rules]},
        )
        result = runner.invoke(app, ["policy", "show", "baseline"])
        assert result.exit_code == 0
        # Should not contain rule rows but still shows header
        assert "rule-1" not in result.output

    def test_description_shown(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "show", "baseline"])
        assert "Baseline filter policy" in result.output


class TestCreatePolicy:
    def test_happy_path(self, authed_config, monkeypatch, tmp_path):
        created = {**SAMPLE_POLICY, "version": 1, "rule_count": 1}
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.create_policy",
            lambda self, **kw: created,
        )
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "create", "baseline", "--file", str(f)])
        assert result.exit_code == 0, result.output
        assert "Created" in result.output
        assert "baseline" in result.output

    def test_with_description(self, authed_config, monkeypatch, tmp_path):
        calls = []

        def mock_create(self, **kw):
            calls.append(kw)
            return {**SAMPLE_POLICY, "version": 1}

        monkeypatch.setattr("sciath_cli.api.SciathAPI.create_policy", mock_create)
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "create", "baseline", "--file", str(f), "--description", "My policy"])
        assert result.exit_code == 0, result.output
        assert calls[0]["description"] == "My policy"

    def test_file_not_found(self, authed_config, tmp_path):
        result = runner.invoke(app, ["policy", "create", "baseline", "--file", str(tmp_path / "missing.json")])
        assert result.exit_code == 1
        assert "File not found" in result.output

    def test_invalid_json(self, authed_config, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        result = runner.invoke(app, ["policy", "create", "baseline", "--file", str(f)])
        assert result.exit_code == 1
        assert "Invalid JSON" in result.output

    def test_api_error(self, authed_config, monkeypatch, tmp_path):
        def raise_err(self, **kw):
            raise SciathAPIError("duplicate name")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.create_policy", raise_err)
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "create", "baseline", "--file", str(f)])
        assert result.exit_code == 1
        assert "duplicate name" in result.output


class TestUpdatePolicy:
    def test_happy_path(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        updated = {**SAMPLE_POLICY, "version": 3, "rule_count": 5}
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.update_policy",
            lambda self, pid, payload: updated,
        )
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "update", "baseline", "--file", str(f)])
        assert result.exit_code == 0, result.output
        assert "Updated" in result.output
        assert "v3" in result.output

    def test_policy_not_found(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "update", "nonexistent", "--file", str(f)])
        assert result.exit_code == 1

    def test_file_not_found(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "update", "baseline", "--file", str(tmp_path / "missing.json")])
        assert result.exit_code == 1
        assert "File not found" in result.output

    def test_invalid_json(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        f = tmp_path / "bad.json"
        f.write_text("{invalid")
        result = runner.invoke(app, ["policy", "update", "baseline", "--file", str(f)])
        assert result.exit_code == 1
        assert "Invalid JSON" in result.output

    def test_api_error(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )

        def raise_err(self, pid, payload):
            raise SciathAPIError("server error")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.update_policy", raise_err)
        f = _make_json_file(tmp_path)
        result = runner.invoke(app, ["policy", "update", "baseline", "--file", str(f)])
        assert result.exit_code == 1
        assert "server error" in result.output


class TestDeletePolicy:
    def test_happy_path_force(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.delete_policy",
            lambda self, pid: {},
        )
        result = runner.invoke(app, ["policy", "delete", "baseline", "--force"])
        assert result.exit_code == 0, result.output
        assert "Deleted" in result.output

    def test_not_found(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["policy", "delete", "nonexistent", "--force"])
        assert result.exit_code == 1

    def test_confirmation_declined(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        result = runner.invoke(app, ["policy", "delete", "baseline"], input="n\n")
        assert result.exit_code == 0  # declined exits 0

    def test_confirmation_accepted(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.delete_policy",
            lambda self, pid: {},
        )
        result = runner.invoke(app, ["policy", "delete", "baseline"], input="y\n")
        assert result.exit_code == 0
        assert "Deleted" in result.output

    def test_api_error(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )

        def raise_err(self, pid):
            raise SciathAPIError("forbidden")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.delete_policy", raise_err)
        result = runner.invoke(app, ["policy", "delete", "baseline", "--force"])
        assert result.exit_code == 1
        assert "forbidden" in result.output


class TestHistoryPolicy:
    def test_happy_path(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        history_items = [
            {"version": 2, "content_hash": "abc123def456", "edited_by_id": "user-uuid-1", "timestamp": "2026-03-15T12:00:00Z"},
            {"version": 1, "content_hash": "old111222333", "edited_by_id": "user-uuid-1", "timestamp": "2026-03-01T10:00:00Z"},
        ]
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.policy_history",
            lambda self, pid: {"items": history_items},
        )
        result = runner.invoke(app, ["policy", "history", "baseline"])
        assert result.exit_code == 0, result.output
        assert "v2" in result.output
        assert "v1" in result.output
        assert "baseline" in result.output

    def test_empty_history(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.policy_history",
            lambda self, pid: {"items": []},
        )
        result = runner.invoke(app, ["policy", "history", "baseline"])
        assert result.exit_code == 0
        assert "No history" in result.output

    def test_not_found(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["policy", "history", "nonexistent"])
        assert result.exit_code == 1

    def test_api_error(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )

        def raise_err(self, pid):
            raise SciathAPIError("timeout")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.policy_history", raise_err)
        result = runner.invoke(app, ["policy", "history", "baseline"])
        assert result.exit_code == 1
        assert "timeout" in result.output


class TestImportVex:
    def test_happy_path(self, authed_config, monkeypatch, tmp_path):
        imported = {**SAMPLE_POLICY, "name": "vendor-import", "version": 1, "rule_count": 5}
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.import_vex_policy",
            lambda self, **kw: imported,
        )
        f = _make_json_file(tmp_path, "vex.json", {"vulnerabilities": []})
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(f)])
        assert result.exit_code == 0, result.output
        assert "Imported" in result.output
        assert "vendor-import" in result.output
        assert "MEDIUM" in result.output

    def test_trust_vendor(self, authed_config, monkeypatch, tmp_path):
        calls = []

        def mock_import(self, **kw):
            calls.append(kw)
            return {**SAMPLE_POLICY, "name": "vendor-import", "version": 1, "rule_count": 5}

        monkeypatch.setattr("sciath_cli.api.SciathAPI.import_vex_policy", mock_import)
        f = _make_json_file(tmp_path, "vex.json", {"vulnerabilities": []})
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(f), "--trust-vendor"])
        assert result.exit_code == 0, result.output
        assert calls[0]["trust_vendor"] is True
        assert "HIGH" in result.output

    def test_with_description(self, authed_config, monkeypatch, tmp_path):
        calls = []

        def mock_import(self, **kw):
            calls.append(kw)
            return {**SAMPLE_POLICY, "name": "vendor-import", "version": 1, "rule_count": 5}

        monkeypatch.setattr("sciath_cli.api.SciathAPI.import_vex_policy", mock_import)
        f = _make_json_file(tmp_path, "vex.json", {"vulnerabilities": []})
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(f), "--description", "From NXP"])
        assert result.exit_code == 0, result.output
        assert calls[0]["description"] == "From NXP"

    def test_file_not_found(self, authed_config, tmp_path):
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(tmp_path / "missing.json")])
        assert result.exit_code == 1
        assert "File not found" in result.output

    def test_invalid_json(self, authed_config, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(f)])
        assert result.exit_code == 1
        assert "Invalid JSON" in result.output

    def test_api_error(self, authed_config, monkeypatch, tmp_path):
        def raise_err(self, **kw):
            raise SciathAPIError("invalid VEX format")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.import_vex_policy", raise_err)
        f = _make_json_file(tmp_path, "vex.json", {"vulnerabilities": []})
        result = runner.invoke(app, ["policy", "import-vex", "vendor-import", "--file", str(f)])
        assert result.exit_code == 1
        assert "invalid VEX format" in result.output


class TestMergePolicy:
    def test_happy_path(self, authed_config, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {
                "items": [
                    p for p in [SAMPLE_POLICY, SAMPLE_POLICY_B]
                    if kw.get("search", "").lower() in p["name"].lower()
                ]
            },
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.get_policy",
            lambda self, pid: SAMPLE_POLICY if pid == "pol-uuid-1234" else SAMPLE_POLICY_B,
        )
        out = tmp_path / "merged.json"
        result = runner.invoke(app, ["policy", "merge", "baseline", "vendor-vex", "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert "Merged" in result.output
        assert out.exists()
        merged = json.loads(out.read_text())
        assert "rules" in merged
        # rule-3 is in both policies; last one wins so 4 unique rules total
        rule_ids = [r["id"] for r in merged["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs in output"

    def test_duplicate_rule_dedup(self, authed_config, monkeypatch, tmp_path):
        """rule-3 exists in both policies; merge should deduplicate (last wins)."""
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {
                "items": [
                    p for p in [SAMPLE_POLICY, SAMPLE_POLICY_B]
                    if kw.get("search", "").lower() in p["name"].lower()
                ]
            },
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.get_policy",
            lambda self, pid: SAMPLE_POLICY if pid == "pol-uuid-1234" else SAMPLE_POLICY_B,
        )
        out = tmp_path / "merged.json"
        result = runner.invoke(app, ["policy", "merge", "baseline", "vendor-vex", "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert "Duplicate" in result.output or "duplicate" in result.output.lower()
        merged = json.loads(out.read_text())
        rule_ids = [r["id"] for r in merged["rules"]]
        assert rule_ids.count("rule-3") == 1
        # The last-wins rule-3 should be from vendor-vex (CVE-2024-5678)
        rule3 = next(r for r in merged["rules"] if r["id"] == "rule-3")
        assert rule3["match"]["value"] == "CVE-2024-5678"

    def test_fewer_than_two_names(self, authed_config):
        result = runner.invoke(app, ["policy", "merge", "only-one"])
        assert result.exit_code == 1
        assert "at least 2" in result.output.lower()

    def test_policy_not_found(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["policy", "merge", "missing1", "missing2"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_api_error_on_list(self, authed_config, monkeypatch):
        def raise_err(self, **kw):
            raise SciathAPIError("network error")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_policies", raise_err)
        result = runner.invoke(app, ["policy", "merge", "a", "b"])
        assert result.exit_code == 1
        assert "network error" in result.output

    def test_api_error_on_get(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {"items": [SAMPLE_POLICY]},
        )

        def raise_err(self, pid):
            raise SciathAPIError("get failed")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.get_policy", raise_err)
        result = runner.invoke(app, ["policy", "merge", "baseline", "baseline"])
        assert result.exit_code == 1
        assert "get failed" in result.output

    def test_default_output_file(self, authed_config, monkeypatch, tmp_path, monkeypatch_cwd=None):
        """Without --output, writes to merged_policy.json in cwd."""
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_policies",
            lambda self, **kw: {
                "items": [
                    p for p in [SAMPLE_POLICY, SAMPLE_POLICY_B]
                    if kw.get("search", "").lower() in p["name"].lower()
                ]
            },
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.get_policy",
            lambda self, pid: SAMPLE_POLICY if pid == "pol-uuid-1234" else SAMPLE_POLICY_B,
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["policy", "merge", "baseline", "vendor-vex"])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "merged_policy.json").exists()
