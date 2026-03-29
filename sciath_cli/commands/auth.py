"""
Auth commands: login, logout, whoami.

Login uses the device code flow already built in api/routers/auth.py:
  POST /api/auth/v1/device/code  → device_code + poll_code
  GET  /api/auth/v1/device/token → api_key once browser authorises
"""
import logging
import time

import httpx
import typer
from rich.live import Live
from rich.spinner import Spinner

from sciath_cli.config import clear_config, load_config, save_config
from sciath_cli.console import console

logger = logging.getLogger(__name__)

app = typer.Typer(help="Authentication commands.")


@app.command()
def login(
    api_url: str = typer.Option(None, "--api-url", envvar="SCIATH_API_URL", help="API base URL"),
) -> None:
    """Authenticate with Sciath via browser."""
    config = load_config()
    if api_url:
        config.api_url = api_url.rstrip("/")

    with httpx.Client(base_url=config.api_url, timeout=15.0) as client:
        try:
            resp = client.post("/api/auth/v1/device/code", json={"client_name": "Sciath CLI"})
            resp.raise_for_status()
        except Exception as exc:
            console.print(f"[red]✗ Could not reach {config.api_url}: {exc}[/red]")
            raise typer.Exit(1)

    data = resp.json()
    device_code = data["device_code"]
    poll_code = data["poll_code"]
    verification_uri = data["verification_uri"]
    expires_in = data.get("expires_in", 900)

    console.print()
    console.print("  [bold]Sciath CLI[/bold]")
    console.print()
    console.print("  To authenticate, open this URL in your browser:")
    console.print()
    console.print(f"    [link={verification_uri}]{verification_uri}[/link]")
    console.print()
    console.print("  Then enter this code:")
    console.print()
    console.print(f"    [bold cyan]{device_code}[/bold cyan]")
    console.print()

    deadline = time.monotonic() + expires_in
    result = None

    with Live(Spinner("dots", text="  Waiting for authentication..."), console=console, refresh_per_second=10):
        with httpx.Client(base_url=config.api_url, timeout=10.0) as client:
            while time.monotonic() < deadline:
                time.sleep(2)
                try:
                    resp = client.get("/api/auth/v1/device/token", params={"poll_code": poll_code})
                    result = resp.json()
                except Exception:
                    logger.debug("auth.poll_error", exc_info=True)
                    continue  # transient network error — keep polling

                if result.get("access_token") or result.get("api_key"):
                    break
                status = result.get("status", "pending")
                if status == "expired" or resp.status_code == 410:
                    console.print("\n[red]✗ Authentication code expired. Try again.[/red]")
                    raise typer.Exit(1)
                if status == "denied":
                    console.print("\n[red]✗ Authentication denied.[/red]")
                    raise typer.Exit(1)
            else:
                console.print("\n[red]✗ Authentication timed out. Try again.[/red]")
                raise typer.Exit(1)

    # Handle OAuth2 or legacy API key response.
    if result.get("access_token"):
        config.access_token = result["access_token"]
        config.refresh_token = result.get("refresh_token")
        from datetime import datetime, timedelta, timezone
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=result.get("expires_in", 3600))
        config.token_expires_at = expires_at.isoformat()
        config.api_key = None  # Clear legacy key if present
    else:
        config.api_key = result["api_key"]

    config.user_email = result.get("user_email", "")
    config.customer_name = result.get("customer_name", "")
    save_config(config)

    console.print(f"[green]✓[/green] Authenticated as [bold]{result.get('user_email', '')}[/bold] ({result.get('customer_name', '')})")
    auth_type = "OAuth2 tokens" if result.get("access_token") else "API key"
    console.print(f"[green]✓[/green] {auth_type} saved to ~/.sciath/config.json")


@app.command()
def logout() -> None:
    """Clear stored credentials."""
    clear_config()
    console.print("[green]✓[/green] Logged out")


@app.command()
def whoami() -> None:
    """Show current authenticated user."""
    config = load_config()
    if not config.has_any_auth:
        console.print("[yellow]Not authenticated.[/yellow] Run [bold]sciath login[/bold] first.")
        raise typer.Exit(1)

    console.print(f"Email:    {config.user_email or '(unknown)'}")
    console.print(f"Customer: {config.customer_name or '(unknown)'}")
    console.print(f"API URL:  {config.api_url}")
    auth_method = "OAuth2" if config.has_oauth2 else "API key (legacy)"
    console.print(f"Auth:     {auth_method}")
    if config.token_expires_at:
        console.print(f"Expires:  {config.token_expires_at}")
    if config.active_project_name:
        console.print(f"Project:  {config.active_project_name}")
