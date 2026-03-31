"""
Shared test fixtures for sciath-cli.
"""

import pytest


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Redirect ~/.sciath config and cache to temp dir for every test."""
    import sciath_cli.cache as cache_module
    import sciath_cli.config as cfg_module

    monkeypatch.setattr(cfg_module, "CONFIG_DIR", tmp_path / ".sciath")
    monkeypatch.setattr(cfg_module, "CONFIG_FILE", tmp_path / ".sciath" / "config.json")
    monkeypatch.delenv("SCIATH_API_URL", raising=False)
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / ".sciath" / "cache")
    yield
