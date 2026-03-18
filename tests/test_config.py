"""
Unit tests for config.py: load, save, clear, env var override, @requires_auth.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import typer

from sciath_cli.config import (
    SciathConfig,
    clear_config,
    load_config,
    requires_auth,
    save_config,
    DEFAULT_API_URL,
)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Redirect ~/.sciath to a temp dir for every test."""
    import sciath_cli.config as cfg_module
    monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath")
    monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath" / "config.json")
    monkeypatch.delenv("SCIATH_API_URL", raising=False)
    yield


def _config_file(tmp_path):
    return tmp_path / ".sciath" / "config.json"


class TestLoadConfig:
    def test_returns_defaults_when_no_file(self):
        config = load_config()
        assert config.api_url == DEFAULT_API_URL
        assert config.api_key is None

    def test_loads_saved_values(self, tmp_path):
        save_config(SciathConfig(api_key="sk_test_123", user_email="kim@acme.com"))
        config = load_config()
        assert config.api_key == "sk_test_123"
        assert config.user_email == "kim@acme.com"

    def test_env_var_overrides_config_file(self, monkeypatch, tmp_path):
        save_config(SciathConfig(api_url="https://api.sciath.io"))
        monkeypatch.setenv("SCIATH_API_URL", "https://staging.sciath.io")
        config = load_config()
        assert config.api_url == "https://staging.sciath.io"

    def test_env_var_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("SCIATH_API_URL", "https://staging.sciath.io/")
        config = load_config()
        assert config.api_url == "https://staging.sciath.io"

    def test_corrupted_config_returns_defaults(self, tmp_path):
        import sciath_cli.config as cfg_module
        cfg_module.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        cfg_module.CONFIG_FILE.write_text("{not valid json")
        config = load_config()
        assert config.api_key is None

    def test_missing_optional_fields_use_defaults(self, tmp_path):
        import sciath_cli.config as cfg_module
        cfg_module.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        cfg_module.CONFIG_FILE.write_text('{"api_key": "sk_x"}')
        config = load_config()
        assert config.api_key == "sk_x"
        assert config.user_email is None


class TestSaveConfig:
    def test_creates_config_dir(self, tmp_path):
        import sciath_cli.config as cfg_module
        save_config(SciathConfig(api_key="sk_test"))
        assert cfg_module.CONFIG_FILE.exists()

    def test_sets_file_permissions_600(self, tmp_path):
        import sciath_cli.config as cfg_module
        save_config(SciathConfig(api_key="sk_test"))
        mode = oct(cfg_module.CONFIG_FILE.stat().st_mode)[-3:]
        assert mode == "600"

    def test_round_trip(self):
        original = SciathConfig(
            api_key="sk_abc",
            user_email="x@y.com",
            customer_name="Acme",
            active_project_id="proj-123",
        )
        save_config(original)
        loaded = load_config()
        assert loaded.api_key == original.api_key
        assert loaded.user_email == original.user_email
        assert loaded.active_project_id == original.active_project_id


class TestClearConfig:
    def test_removes_file(self):
        save_config(SciathConfig(api_key="sk_x"))
        clear_config()
        config = load_config()
        assert config.api_key is None

    def test_idempotent_when_no_file(self):
        clear_config()  # should not raise


class TestRequiresAuth:
    def test_passes_config_to_function(self):
        save_config(SciathConfig(api_key="sk_live_test"))

        received = {}

        @requires_auth
        def dummy(config=None):
            received["config"] = config

        dummy()
        assert received["config"].api_key == "sk_live_test"

    def test_exits_when_no_api_key(self):
        import click

        @requires_auth
        def dummy(config=None):
            pass

        with pytest.raises(click.exceptions.Exit):
            dummy()

    def test_preserves_function_name(self):
        @requires_auth
        def my_command(config=None):
            pass

        assert my_command.__name__ == "my_command"
