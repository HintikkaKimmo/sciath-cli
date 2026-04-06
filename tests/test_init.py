"""Tests for sciath init command — Yocto build environment setup.

Hard requirement: never break the Yocto build. Every test validates
that the init command either succeeds safely or fails without modifying
build files.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from sciath_cli.main import app

runner = CliRunner()


@pytest.fixture
def yocto_env(tmp_path: Path) -> Path:
    """Minimal Yocto build environment for init testing."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    conf = build_dir / "conf"
    conf.mkdir()
    (conf / "local.conf").write_text(
        'MACHINE ?= "raspberrypi4-64"\nDISTRO ?= "poky"\n'
    )
    (conf / "bblayers.conf").write_text(
        'BBLAYERS ?= " \\\n'
        '  /home/user/poky/meta \\\n'
        '  /home/user/poky/meta-poky \\\n'
        '"\n'
    )
    (build_dir / "tmp").mkdir()
    return build_dir


class TestDetectBuildDir:
    def test_explicit_build_dir(self, yocto_env: Path):
        result = runner.invoke(app, ["init", "yocto", "--build-dir", str(yocto_env), "--dry-run"])
        assert result.exit_code == 0
        assert "Build directory" in result.output

    def test_rejects_non_yocto_dir(self, tmp_path: Path):
        result = runner.invoke(app, ["init", "yocto", "--build-dir", str(tmp_path), "--dry-run"])
        assert result.exit_code == 1
        assert "local.conf" in result.output

    def test_detects_from_builddir_env(self, yocto_env: Path, monkeypatch):
        monkeypatch.setenv("BUILDDIR", str(yocto_env))
        monkeypatch.chdir(yocto_env.parent)  # Not in build dir
        result = runner.invoke(app, ["init", "yocto", "--dry-run"])
        assert result.exit_code == 0


class TestDryRun:
    def test_shows_actions_without_modifying(self, yocto_env: Path):
        result = runner.invoke(app, ["init", "yocto", "--build-dir", str(yocto_env), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output
        assert "would extract" in result.output or "would append" in result.output
        # Verify nothing was modified
        local_conf = (yocto_env / "conf" / "local.conf").read_text()
        assert "SCIATH_API_KEY" not in local_conf


class TestLayerExtraction:
    def test_extracts_meta_layer(self, yocto_env: Path):
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--no-configure", "--api-key", "test"],
            input="test-project\n",
        )
        layer_path = yocto_env.parent / "sources" / "meta-sciath"
        assert layer_path.exists()
        assert (layer_path / "classes" / "sciath.bbclass").exists()
        assert (layer_path / "conf" / "layer.conf").exists()

    def test_skips_if_layer_exists(self, yocto_env: Path):
        layer_path = yocto_env.parent / "sources" / "meta-sciath"
        layer_path.mkdir(parents=True)
        (layer_path / "marker").write_text("existing")

        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--no-configure"],
            input="test\ntest-project\n",
        )
        # Should not overwrite
        assert (layer_path / "marker").read_text() == "existing"


class TestLocalConfModification:
    def test_appends_sciath_config(self, yocto_env: Path):
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--api-key", "sk-test", "--project", "my-project"],
        )
        local_conf = (yocto_env / "conf" / "local.conf").read_text()
        assert 'SCIATH_API_KEY = "sk-test"' in local_conf
        assert 'SCIATH_PROJECT = "my-project"' in local_conf
        assert 'SCIATH_ENABLED = "0"' in local_conf  # Disabled by default!

    def test_creates_backup(self, yocto_env: Path):
        original = (yocto_env / "conf" / "local.conf").read_text()
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--api-key", "sk-test", "--project", "my-project"],
        )
        backup = yocto_env / "conf" / "local.conf.sciath-backup"
        assert backup.exists()
        assert backup.read_text() == original

    def test_skips_if_already_configured(self, yocto_env: Path):
        # Pre-configure
        with open(yocto_env / "conf" / "local.conf", "a") as f:
            f.write('SCIATH_API_KEY = "existing"\n')

        result = runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--api-key", "new-key", "--project", "proj"],
        )
        assert "already configured" in result.output or "already" in result.output.lower()

    def test_no_configure_flag_skips(self, yocto_env: Path):
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--no-configure"],
            input="test\ntest-project\n",
        )
        local_conf = (yocto_env / "conf" / "local.conf").read_text()
        assert "SCIATH_API_KEY" not in local_conf


class TestRollback:
    def test_rollback_restores_files(self, yocto_env: Path):
        original_local = (yocto_env / "conf" / "local.conf").read_text()

        # Run init to create backups + modify
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--api-key", "sk-test", "--project", "proj"],
        )
        # Verify modified
        assert "SCIATH_API_KEY" in (yocto_env / "conf" / "local.conf").read_text()

        # Rollback
        result = runner.invoke(app, ["init", "yocto", "--build-dir", str(yocto_env), "--rollback"])
        assert result.exit_code == 0
        assert "Restored" in result.output
        assert (yocto_env / "conf" / "local.conf").read_text() == original_local

    def test_rollback_no_backup(self, yocto_env: Path):
        result = runner.invoke(app, ["init", "yocto", "--build-dir", str(yocto_env), "--rollback"])
        assert "Nothing to rollback" in result.output


class TestNeverBreakBuild:
    """The critical invariant: init must never leave the build in a broken state."""

    def test_enabled_defaults_to_zero(self, yocto_env: Path):
        """SCIATH_ENABLED must always default to 0 (disabled)."""
        runner.invoke(
            app,
            ["init", "yocto", "--build-dir", str(yocto_env), "--api-key", "sk-test", "--project", "proj"],
        )
        local_conf = (yocto_env / "conf" / "local.conf").read_text()
        assert 'SCIATH_ENABLED = "0"' in local_conf

    def test_non_yocto_dir_not_modified(self, tmp_path: Path):
        """Running init on a non-Yocto dir must not create any files."""
        files_before = set(tmp_path.iterdir())
        runner.invoke(app, ["init", "yocto", "--build-dir", str(tmp_path)])
        files_after = set(tmp_path.iterdir())
        assert files_before == files_after
