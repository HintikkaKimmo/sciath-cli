"""
Project commands: list, create, select.
"""
from typing import Any

import typer
from rich.table import Table

from sciath_cli.api import SciathAPI, SciathAPIError
from sciath_cli.config import requires_auth, save_config
from sciath_cli.console import console

app = typer.Typer(help="Manage projects.")


@app.command("list")
@requires_auth
def list_projects(config: Any = None) -> None:
    """List projects for the current customer."""
    with SciathAPI(config) as api:
        try:
            result = api.list_projects()
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    if not items:
        console.print("[dim]No projects found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Build System")
    table.add_column("Architecture")
    table.add_column("ID", style="dim")

    for p in items:
        active = " [green]●[/green]" if p["id"] == config.active_project_id else ""
        table.add_row(
            p["name"] + active,
            p.get("build_system", ""),
            p.get("architecture", ""),
            p["id"][:8],
        )

    console.print(table)


@app.command()
@requires_auth
def create(name: str = typer.Argument(..., help="Project name"), config: Any = None) -> None:
    """Create a new project."""
    with SciathAPI(config) as api:
        try:
            # Projects require a customer_id; derive from user's customer
            # The API will scope this to the authenticated customer
            result = api.create_project(customer_id="", name=name)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    console.print(f"[green]✓[/green] Created project [bold]{result['name']}[/bold] ({result['id'][:8]})")


@app.command()
@requires_auth
def select(name: str = typer.Argument(..., help="Project name or ID"), config: Any = None) -> None:
    """Set the active project for subsequent commands."""
    with SciathAPI(config) as api:
        try:
            result = api.list_projects()
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    match = next(
        (p for p in items if p["name"] == name or p["id"].startswith(name)),
        None,
    )
    if not match:
        console.print(f"[red]✗ Project not found: {name}[/red]")
        raise typer.Exit(1)

    config.active_project_id = match["id"]
    config.active_project_name = match["name"]
    save_config(config)
    console.print(f"[green]✓[/green] Active project set to [bold]{match['name']}[/bold]")


@app.command()
@requires_auth
def info(config: Any = None) -> None:
    """Show active project details."""
    if not config.active_project_id:
        console.print("[yellow]No active project.[/yellow] Run [bold]sciath project select <name>[/bold] first.")
        raise typer.Exit(1)

    console.print(f"Project: [bold]{config.active_project_name}[/bold]")
    console.print(f"ID:      {config.active_project_id}")
