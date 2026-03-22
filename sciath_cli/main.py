"""
Sciath CLI entry point.

Command structure:
  sciath login / logout / whoami         (auth, registered at root)
  sciath project list/create/select/info
  sciath scan run/status/list/reanalyse
  sciath assess list/approve/reject
  sciath report [scan-id]
"""
import typer

from sciath_cli import __version__
from sciath_cli.commands import assess, auth, project, report, scan, vex

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


@app.command("mcp")
def mcp_server():
    """Start MCP server for editor integration (Claude Code, Cursor, etc.)."""
    import asyncio

    from sciath_cli.mcp_server import run_server
    asyncio.run(run_server())


@app.callback(invoke_without_command=True)
def version_flag(
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit", is_eager=True),
):
    if version:
        typer.echo(f"sciath {__version__}")
        raise typer.Exit()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
