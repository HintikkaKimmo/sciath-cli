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

from sciath_cli.commands import auth, project, scan, assess, report
from sciath_cli import __version__

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
