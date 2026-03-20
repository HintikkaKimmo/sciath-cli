"""
Auth commands: login, logout, whoami.

Login uses the device code flow already built in api/routers/auth.py:
  POST /api/auth/v1/device/code  → device_code + poll_code
  GET  /api/auth/v1/device/token → api_key once browser authorises
"""
import time

import httpx
import typer
from rich.live import Live
from rich.spinner import Spinner

from sciath_cli.config import clear_config, load_config, save_config
from sciath_cli.console import console

app = typer.Typer(help="Authentication commands.")


@app.command()
def login(
    api_url: str = typer.Option(None, "--api-url", envvar="SCIATH_API_URL", help="API base URL"),
):
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
                    continue  # transient network error — keep polling

                if result.get("api_key"):
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

    config.api_key = result["api_key"]
    config.user_email = result["user_email"]
    config.customer_name = result["customer_name"]
    save_config(config)

    console.print(f"[green]✓[/green] Authenticated as [bold]{result['user_email']}[/bold] ({result['customer_name']})")
    console.print("[green]✓[/green] Credentials saved to ~/.sciath/config.json")


@app.command()
def logout():
    """Clear stored credentials."""
    clear_config()
    console.print("[green]✓[/green] Logged out")


@app.command()
def whoami():
    """Show current authenticated user."""
    config = load_config()
    if not config.api_key:
        console.print("[yellow]Not authenticated.[/yellow] Run [bold]sciath login[/bold] first.")
        raise typer.Exit(1)

    console.print(f"Email:    {config.user_email or '(unknown)'}")
    console.print(f"Customer: {config.customer_name or '(unknown)'}")
    console.print(f"API URL:  {config.api_url}")
    if config.active_project_name:
        console.print(f"Project:  {config.active_project_name}")
