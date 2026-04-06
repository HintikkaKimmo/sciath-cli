"""
Sciath CLI entry point.

Command structure:
  sciath login / logout / whoami         (auth, registered at root)
  sciath project list/create/select/info
  sciath scan run/status/list/reanalyse
  sciath assess list/approve/reject
  sciath report <scan-id> [--format pdf|vex|csaf|spdx]
"""
import logging
import sys

import typer

from sciath_cli import __version__
from sciath_cli.commands import assess, auth, init, policy, project, report, scan, vex

app = typer.Typer(
    name="sciath",
    help="CRA compliance automation for embedded Linux.",
    no_args_is_help=True,
    add_completion=False,
)

# Auth commands registered at root level (sciath login / logout / whoami)
app.command("login")(auth.login)
app.command("logout")(auth.logout)
app.command("whoami")(auth.whoami)

# Subcommand groups
app.add_typer(project.app, name="project")
app.add_typer(scan.app, name="scan")
app.add_typer(assess.app, name="assess")
app.add_typer(report.app, name="report")
app.add_typer(vex.app, name="vex")
app.add_typer(policy.app, name="policy")
app.add_typer(init.app, name="init")


cache_app = typer.Typer(help="Manage the local scan cache.")


@cache_app.command("clear")
def cache_clear() -> None:
    """Remove all cached scan results."""
    from sciath_cli.cache import clear_all
    from sciath_cli.console import console
    count = clear_all()
    console.print(f"[green]Cleared {count} cached scan result(s).[/green]")


app.add_typer(cache_app, name="cache")


@app.command("mcp")
def mcp_server() -> None:
    """Start MCP server for editor integration (Claude Code, Cursor, etc.)."""
    import asyncio

    from sciath_cli.mcp_server import run_server
    asyncio.run(run_server())


@app.callback(invoke_without_command=True)
def main_callback(
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit", is_eager=True),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging to stderr"),
) -> None:
    if version:
        typer.echo(f"sciath {__version__}")
        raise typer.Exit()

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
