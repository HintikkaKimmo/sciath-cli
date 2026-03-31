"""
Tests for the vex export command.

Covers:
- Happy path with default format (vex_cdx)
- Invalid format rejection
- NotFoundError handling
- ValidationError handling (--validate flag)
- Custom --output path
- IOError on write
"""
import pytest
from typer.testing import CliRunner

from sciath_cli.config import SciathConfig, save_config
from sciath_cli.main import app

runner = CliRunner()

FAKE_CDX = b'{"bomFormat": "CycloneDX"}'
SCAN_ID = "scan-uuid-1234"


@pytest.fixture
def authed_config():
    save_config(SciathConfig(
        api_key="sk_test",
        user_email="kim@acme.com",
        customer_name="Acme Corp",
    ))


def _patch_vex_happy(monkeypatch, content: bytes = FAKE_CDX):
    """Patch _resolve_scan_id (passthrough) and export_cdx (return bytes)."""
    monkeypatch.setattr(
        "sciath_cli.commands.scan._resolve_scan_id",
        lambda api, sid: sid,
    )
    monkeypatch.setattr(
        "sciath_cli.api.SciathAPI.export_cdx",
        lambda self, sid, **kw: content,
    )


class TestVexHappyPath:
    def test_default_format_creates_file(self, authed_config, monkeypatch, tmp_path):
        _patch_vex_happy(monkeypatch)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["vex", "vex", SCAN_ID])

        assert result.exit_code == 0, result.output
        expected_file = tmp_path / f"sciath_{SCAN_ID[:8]}_vex_cdx.json"
        assert expected_file.exists()
        assert expected_file.read_bytes() == FAKE_CDX

    def test_custom_output_path(self, authed_config, monkeypatch, tmp_path):
        _patch_vex_happy(monkeypatch)
        out_file = tmp_path / "custom_output.json"

        result = runner.invoke(app, ["vex", "vex", SCAN_ID, "--output", str(out_file)])

        assert result.exit_code == 0, result.output
        assert out_file.exists()
        assert out_file.read_bytes() == FAKE_CDX


class TestVexInvalidFormat:
    def test_unknown_format_exits_1(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.commands.scan._resolve_scan_id",
            lambda api, sid: sid,
        )
        result = runner.invoke(app, ["vex", "vex", SCAN_ID, "--format", "nope"])

        assert result.exit_code == 1
        assert "nope" in result.output
        # Should list valid formats
        assert "vex_cdx" in result.output


class TestVexNotFound:
    def test_not_found_exits_1(self, authed_config, monkeypatch):
        from sciath_cli.api import NotFoundError

        monkeypatch.setattr(
            "sciath_cli.commands.scan._resolve_scan_id",
            lambda api, sid: sid,
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.export_cdx",
            lambda self, sid, **kw: (_ for _ in ()).throw(NotFoundError("not found")),
        )

        result = runner.invoke(app, ["vex", "vex", SCAN_ID])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()


class TestVexValidationError:
    def test_validation_error_exits_1(self, authed_config, monkeypatch):
        from sciath_cli.api import ValidationError

        monkeypatch.setattr(
            "sciath_cli.commands.scan._resolve_scan_id",
            lambda api, sid: sid,
        )
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.export_cdx",
            lambda self, sid, **kw: (_ for _ in ()).throw(
                ValidationError("Schema validation failed: missing required field 'bomFormat'")
            ),
        )

        result = runner.invoke(app, ["vex", "vex", SCAN_ID, "--validate"])

        assert result.exit_code == 1
        assert "validation" in result.output.lower()


class TestVexIOError:
    def test_write_failure_exits_1(self, authed_config, monkeypatch, tmp_path):
        _patch_vex_happy(monkeypatch)

        # Point to a path that cannot be written (non-existent directory)
        bad_path = str(tmp_path / "no_such_dir" / "output.json")

        result = runner.invoke(app, ["vex", "vex", SCAN_ID, "--output", bad_path])

        assert result.exit_code == 1
        assert "could not write" in result.output.lower()
