"""
Config and credential management.

Precedence for api_url (highest → lowest):
  1. SCIATH_API_URL environment variable
  2. api_url in ~/.sciath/config.json
  3. Default: https://api.sciath.io
"""
import os
from pathlib import Path
from typing import Optional

import typer
from pydantic import BaseModel

CONFIG_DIR = Path.home() / ".sciath"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_API_URL = "https://api.sciath.io"


class SciathConfig(BaseModel):
    api_url: str = DEFAULT_API_URL
    api_key: Optional[str] = None
    user_email: Optional[str] = None
    customer_name: Optional[str] = None
    active_project_id: Optional[str] = None
    active_project_name: Optional[str] = None


def load_config() -> SciathConfig:
    """Load config from disk, applying env var overrides."""
    config = SciathConfig()
    if CONFIG_FILE.exists():
        import json
        try:
            data = json.loads(CONFIG_FILE.read_text())
            config = SciathConfig(**data)
        except Exception:
            pass  # corrupted config — start fresh

    env_url = os.environ.get("SCIATH_API_URL")
    if env_url:
        config.api_url = env_url.rstrip("/")

    return config


def save_config(config: SciathConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(config.model_dump_json(indent=2))
    CONFIG_FILE.chmod(0o600)


def clear_config() -> None:
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


def requires_auth(func):
    """
    Decorator for commands that need a valid API key.

    Injects `config` as a keyword argument. Exits with a clear message
    if the user isn't authenticated.

    Also strips `config` from the Typer-visible function signature so
    Typer doesn't try to parse it as a CLI parameter.
    """
    import inspect
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        config = load_config()
        if not config.api_key:
            from rich.console import Console
            Console().print(
                "[red]Not authenticated.[/red] Run [bold]sciath login[/bold] first."
            )
            raise typer.Exit(1)
        return func(*args, config=config, **kwargs)

    # Remove `config` from the signature Typer introspects — it's injected
    # by this decorator, not parsed from the CLI.
    sig = inspect.signature(func)
    params = [p for p in sig.parameters.values() if p.name != "config"]
    wrapper.__signature__ = sig.replace(parameters=params)

    return wrapper
