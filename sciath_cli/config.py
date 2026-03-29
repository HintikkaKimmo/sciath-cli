"""
Config and credential management.

Precedence for api_url (highest → lowest):
  1. SCIATH_API_URL environment variable
  2. api_url in ~/.sciath/config.json
  3. Default: https://api.sciath.io
"""
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import typer
from pydantic import BaseModel
from typing_extensions import ParamSpec

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".sciath"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_API_URL = "https://api.sciath.io"


class SciathConfig(BaseModel):
    api_url: str = DEFAULT_API_URL
    api_key: Optional[str] = None            # Legacy API key (migration compat)
    access_token: Optional[str] = None       # OAuth2 access token
    refresh_token: Optional[str] = None      # OAuth2 refresh token
    token_expires_at: Optional[str] = None   # ISO 8601 expiry timestamp
    user_email: Optional[str] = None
    customer_name: Optional[str] = None
    active_project_id: Optional[str] = None
    active_project_name: Optional[str] = None

    @property
    def has_oauth2(self) -> bool:
        return bool(self.access_token)

    @property
    def has_any_auth(self) -> bool:
        return bool(self.access_token or self.api_key)


def load_config() -> SciathConfig:
    """Load config from disk, applying env var overrides."""
    config = SciathConfig()
    if CONFIG_FILE.exists():
        import json
        try:
            data = json.loads(CONFIG_FILE.read_text())
            config = SciathConfig(**data)
        except Exception:
            logger.warning("config.corrupt path=%s", CONFIG_FILE, exc_info=True)

    env_url = os.environ.get("SCIATH_API_URL")
    if env_url:
        config.api_url = env_url.rstrip("/")

    logger.debug("config.loaded api_url=%s has_auth=%s", config.api_url, config.has_any_auth)
    return config


def save_config(config: SciathConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(config.model_dump_json(indent=2))
    CONFIG_FILE.chmod(0o600)


def clear_config() -> None:
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()


P = ParamSpec("P")
R = TypeVar("R")


def requires_auth(func: Callable[P, R]) -> Callable[..., R]:
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
    def wrapper(*args: Any, **kwargs: Any) -> R:
        config = load_config()
        if not config.has_any_auth:
            from rich.console import Console
            Console().print(
                "[red]Not authenticated.[/red] Run [bold]sciath login[/bold] first."
            )
            raise typer.Exit(1)
        return func(*args, config=config, **kwargs)  # type: ignore[arg-type]

    # Remove `config` from the signature Typer introspects — it's injected
    # by this decorator, not parsed from the CLI.
    sig = inspect.signature(func)
    params = [p for p in sig.parameters.values() if p.name != "config"]
    wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]

    return wrapper
