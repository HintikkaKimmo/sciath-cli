"""Tests for project commands: list, create, select, info."""

import pytest
from typer.testing import CliRunner

from sciath_cli.api import SciathAPIError
from sciath_cli.config import SciathConfig, load_config, save_config
from sciath_cli.main import app

runner = CliRunner()

PROJ_A = {
    "id": "aaaa1111-0000-0000-0000-000000000000",
    "name": "gateway-fw",
    "build_system": "yocto",
    "architecture": "arm64",
}
PROJ_B = {
    "id": "bbbb2222-0000-0000-0000-000000000000",
    "name": "sensor-hub",
    "build_system": "buildroot",
    "architecture": "armhf",
}


@pytest.fixture()
def authed_config():
    save_config(SciathConfig(api_key="sk_test", user_email="kim@acme.com", customer_name="Acme Corp"))


# ── list ───────────────────────────────────────────────────────────────────


class TestListProjects:
    def test_happy_path_with_active_marker(self, authed_config, monkeypatch):
        """Table renders projects with a green dot on the active one."""
        save_config(SciathConfig(
            api_key="sk_test",
            user_email="kim@acme.com",
            customer_name="Acme Corp",
            active_project_id=PROJ_A["id"],
        ))
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": [PROJ_A, PROJ_B]},
        )
        result = runner.invoke(app, ["project", "list"])
        assert result.exit_code == 0
        assert "gateway-fw" in result.output
        assert "sensor-hub" in result.output
        assert "yocto" in result.output
        assert "buildroot" in result.output

    def test_empty_list(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": []},
        )
        result = runner.invoke(app, ["project", "list"])
        assert result.exit_code == 0
        assert "No projects found" in result.output

    def test_api_error(self, authed_config, monkeypatch):
        def _raise(self, **kw):
            raise SciathAPIError("connection refused")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.list_projects", _raise)
        result = runner.invoke(app, ["project", "list"])
        assert result.exit_code == 1
        assert "connection refused" in result.output


# ── create ─────────────────────────────────────────────────────────────────


class TestCreateProject:
    def test_happy_path(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.create_project",
            lambda self, **kw: {
                "id": "cccc3333-0000-0000-0000-000000000000",
                "name": kw["name"],
                "build_system": kw.get("build_system", "yocto"),
                "architecture": kw.get("architecture", ""),
            },
        )
        result = runner.invoke(app, ["project", "create", "my-proj", "-b", "yocto", "-a", "arm64"])
        assert result.exit_code == 0
        assert "my-proj" in result.output
        assert "cccc3333" in result.output

    def test_api_error(self, authed_config, monkeypatch):
        def _raise(self, **kw):
            raise SciathAPIError("403 Forbidden")

        monkeypatch.setattr("sciath_cli.api.SciathAPI.create_project", _raise)
        result = runner.invoke(app, ["project", "create", "bad-proj"])
        assert result.exit_code == 1
        assert "403 Forbidden" in result.output


# ── select ─────────────────────────────────────────────────────────────────


class TestSelectProject:
    def test_match_by_name(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": [PROJ_A, PROJ_B]},
        )
        result = runner.invoke(app, ["project", "select", "sensor-hub"])
        assert result.exit_code == 0
        assert "sensor-hub" in result.output

        cfg = load_config()
        assert cfg.active_project_id == PROJ_B["id"]
        assert cfg.active_project_name == "sensor-hub"

    def test_match_by_id_prefix(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": [PROJ_A, PROJ_B]},
        )
        result = runner.invoke(app, ["project", "select", "aaaa1111"])
        assert result.exit_code == 0
        assert "gateway-fw" in result.output

        cfg = load_config()
        assert cfg.active_project_id == PROJ_A["id"]

    def test_not_found(self, authed_config, monkeypatch):
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": [PROJ_A]},
        )
        result = runner.invoke(app, ["project", "select", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_config_persistence(self, authed_config, monkeypatch):
        """After select, load_config() returns the active project."""
        monkeypatch.setattr(
            "sciath_cli.api.SciathAPI.list_projects",
            lambda self, **kw: {"items": [PROJ_A]},
        )
        runner.invoke(app, ["project", "select", "gateway-fw"])

        cfg = load_config()
        assert cfg.active_project_id == PROJ_A["id"]
        assert cfg.active_project_name == "gateway-fw"


# ── info ───────────────────────────────────────────────────────────────────


class TestProjectInfo:
    def test_happy_path(self, authed_config):
        save_config(SciathConfig(
            api_key="sk_test",
            user_email="kim@acme.com",
            customer_name="Acme Corp",
            active_project_id=PROJ_A["id"],
            active_project_name=PROJ_A["name"],
        ))
        result = runner.invoke(app, ["project", "info"])
        assert result.exit_code == 0
        assert "gateway-fw" in result.output
        assert PROJ_A["id"] in result.output

    def test_no_active_project(self, authed_config):
        result = runner.invoke(app, ["project", "info"])
        assert result.exit_code == 1
        assert "No active project" in result.output
