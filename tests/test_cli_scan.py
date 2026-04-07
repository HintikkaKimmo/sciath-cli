"""
Integration tests for scan commands via CliRunner + mock API.
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
        active_project_id="proj-uuid-1234",
    ))


@pytest.fixture
def sbom_file(tmp_path):
    sbom = tmp_path / "firmware.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}))
    return sbom


def _make_api(responses: list[tuple[int, dict]], monkeypatch):
    """Patch SciathAPI to return canned responses in sequence."""
    call_count = [0]

    def _request(self, method, path, **kwargs):
        idx = min(call_count[0], len(responses) - 1)
        call_count[0] += 1
        status, body = responses[idx]
        if status == 200:
            return body
        from sciath_cli.api import AuthError, NotFoundError, ServerError, ValidationError
        if status == 401:
            raise AuthError("Not authenticated")
        if status == 404:
            raise NotFoundError("Not found")
        if status == 422:
            raise ValidationError("Validation error")
        raise ServerError(f"Server error {status}", status_code=status)

    import sciath_cli.api as api_module
    monkeypatch.setattr(api_module.SciathAPI, "_request", _request)


class TestRunScan:
    def test_happy_path_displays_summary(self, authed_config, sbom_file, monkeypatch):
        scan_created = {"id": "scan-uuid-abcd", "status": "draft"}
        analyse_ok = {"status": "ok", "assessments": 10}
        status_ok = {
            "id": "scan-uuid-abcd",
            "status": "triage",
            "version_label": "cli-123",
            "total_components": 50,
            "total_vulnerabilities": 20,
            "suppressed_count": 15,
            "analysed_at": "2026-03-17T10:00:00Z",
        }
        _make_api([(200, scan_created), (200, analyse_ok), (200, status_ok)], monkeypatch)
        monkeypatch.setattr("sciath_cli.commands.scan.time.sleep", lambda _: None)

        result = runner.invoke(app, ["scan", "run", str(sbom_file)])
        assert result.exit_code == 0, result.output
        assert "TRIAGE" in result.output
        assert "50" in result.output  # total_components

    def test_file_not_found_exits_1(self, authed_config, tmp_path):
        result = runner.invoke(app, ["scan", "run", str(tmp_path / "missing.json")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_no_project_exits_1(self, tmp_path, monkeypatch):
        import sciath_cli.config as cfg_module
        monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath")
        monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath" / "config.json")
        save_config(SciathConfig(api_key="sk_test"))  # no active_project_id

        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        result = runner.invoke(app, ["scan", "run", str(sbom)])
        assert result.exit_code == 1
        assert "project" in result.output.lower()

    def test_analyse_succeeds_with_summary(self, authed_config, sbom_file, monkeypatch):
        """Successful scan displays summary with status."""
        scan_created = {"id": "scan-uuid-ok", "status": "draft"}
        analyse_ok = {"status": "ok", "assessments": 5}
        status_ok = {
            "id": "scan-uuid-ok",
            "status": "triage",
            "version_label": "cli-123",
            "total_components": 10,
            "total_vulnerabilities": 5,
            "suppressed_count": 3,
            "analysed_at": "2026-03-17T10:00:00Z",
        }
        assessments = {"items": []}

        _make_api(
            [(200, scan_created), (200, analyse_ok), (200, status_ok), (200, assessments)],
            monkeypatch,
        )
        monkeypatch.setattr("sciath_cli.commands.scan.time.sleep", lambda _: None)

        result = runner.invoke(app, ["scan", "run", str(sbom_file)])
        assert result.exit_code == 0, result.output
        assert "TRIAGE" in result.output

    def test_all_retries_exhausted_shows_scan_id(self, authed_config, sbom_file, monkeypatch):
        from sciath_cli.api import ServerError

        scan_created = {"id": "scan-uuid-fail", "status": "draft"}
        call_count = [0]

        def _request(self, method, path, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return scan_created
            raise ServerError("503", status_code=503)

        import sciath_cli.api as api_module
        monkeypatch.setattr(api_module.SciathAPI, "_request", _request)
        monkeypatch.setattr("sciath_cli.commands.scan.time.sleep", lambda _: None)

        result = runner.invoke(app, ["scan", "run", str(sbom_file)])
        assert result.exit_code == 1
        assert "scan-uuid-fail" in result.output

    def test_unauthenticated_exits_1(self, tmp_path, sbom_file, monkeypatch):
        import sciath_cli.config as cfg_module
        monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath2")
        monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath2" / "config.json")
        result = runner.invoke(app, ["scan", "run", str(sbom_file)])
        assert result.exit_code == 1
        assert "login" in result.output.lower()


class TestAutoDiscover:
    def test_auto_discover_happy_path(self, authed_config, tmp_path, monkeypatch):
        """--auto-discover calls discovery module and submits the bundle."""
        from sciath_cli.discovery.base import ArtifactBundle

        # Create a fake build dir with SBOM
        sbom = tmp_path / "sbom.spdx.json"
        sbom.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')

        bundle = ArtifactBundle(
            sbom=sbom, sbom_format="spdx",
            yocto_machine="rpi4", build_system="yocto",
        )

        monkeypatch.setattr(
            "sciath_cli.discovery.auto_discover",
            lambda build_dir, build_system="": bundle,
        )

        scan_created = {"id": "scan-auto-uuid", "status": "draft"}
        analyse_ok = {"status": "ok"}
        status_ok = {
            "id": "scan-auto-uuid", "status": "triage",
            "version_label": "yocto-rpi4-123",
            "total_components": 30, "total_vulnerabilities": 100,
            "suppressed_count": 80, "analysed_at": "2026-04-07T10:00:00Z",
        }
        _make_api([(200, scan_created), (200, analyse_ok), (200, status_ok)], monkeypatch)
        monkeypatch.setattr("sciath_cli.commands.scan.time.sleep", lambda _: None)

        result = runner.invoke(app, [
            "scan", "run", "--auto-discover",
            "--build-dir", str(tmp_path),
        ])
        assert result.exit_code == 0, result.output
        assert "TRIAGE" in result.output

    def test_auto_discover_no_sbom_exits_1(self, authed_config, tmp_path, monkeypatch):
        """--auto-discover fails gracefully when no SBOM found."""
        from sciath_cli.discovery.base import ArtifactBundle

        bundle = ArtifactBundle(build_system="yocto")  # no SBOM

        monkeypatch.setattr(
            "sciath_cli.discovery.auto_discover",
            lambda build_dir, build_system="": bundle,
        )

        result = runner.invoke(app, [
            "scan", "run", "--auto-discover",
            "--build-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "SBOM" in result.output

    def test_auto_discover_detection_failure_exits_1(self, authed_config, tmp_path, monkeypatch):
        """--auto-discover exits 1 when no build system is detected."""
        def _fail(build_dir, build_system=""):
            raise RuntimeError("Could not detect build system")

        monkeypatch.setattr(
            "sciath_cli.discovery.auto_discover",
            _fail,
        )

        result = runner.invoke(app, [
            "scan", "run", "--auto-discover",
            "--build-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "Discovery failed" in result.output

    def test_auto_discover_no_project_exits_1(self, tmp_path, monkeypatch):
        """--auto-discover without a project configured exits 1."""
        from sciath_cli.discovery.base import ArtifactBundle

        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        bundle = ArtifactBundle(sbom=sbom, sbom_format="cyclonedx", build_system="yocto")

        monkeypatch.setattr(
            "sciath_cli.discovery.auto_discover",
            lambda build_dir, build_system="": bundle,
        )

        import sciath_cli.config as cfg_module
        from sciath_cli.config import SciathConfig, save_config
        monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath3")
        monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath3" / "config.json")
        save_config(SciathConfig(api_key="sk_test"))  # no active_project_id

        result = runner.invoke(app, [
            "scan", "run", "--auto-discover",
            "--build-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "project" in result.output.lower()
