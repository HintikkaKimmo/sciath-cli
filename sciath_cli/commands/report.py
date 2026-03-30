"""Report command — generate and download compliance reports from the Sciath API."""
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from sciath_cli.api import NotFoundError, SciathAPI, SciathAPIError
from sciath_cli.config import requires_auth
from sciath_cli.console import console

app = typer.Typer(
    help="Generate and download compliance reports.",
    invoke_without_command=True,
)

_FORMAT_MAP = {
    "pdf":  "article13",
    "vex":  "vex_cdx",
    "csaf": "vex_csaf",
    "spdx": "sbom_spdx",
}
_POLL_INTERVAL = 3   # seconds between status polls
_POLL_MAX      = 60  # max polls (3 min ceiling)


@app.callback(invoke_without_command=True)
@requires_auth
def report(
    ctx: typer.Context,
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID (full or short prefix)"),
    fmt: str = typer.Option("pdf", "--format", "-f", help="Output format: pdf, vex, csaf, spdx"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    config: Any = None,
) -> None:
    """Generate and download a compliance report (Article 13 PDF, CycloneDX VEX, CSAF)."""
    if ctx.invoked_subcommand is not None:
        return
    if scan_id is None:
        console.print("Usage: sciath report <scan-id> [--format pdf|vex|csaf|spdx]")
        raise typer.Exit(1)

    api_format = _FORMAT_MAP.get(fmt)
    if not api_format:
        console.print(f"[red]✗ Unknown format '{fmt}'. Choose: pdf, vex, csaf, spdx[/red]")
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        # Resolve short prefix to full UUID
        from sciath_cli.commands.scan import _resolve_scan_id
        scan_id = _resolve_scan_id(api, scan_id)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            task = p.add_task("Requesting report generation…")

            # 1. Request generation
            try:
                report_meta = api.generate_report(scan_id, api_format)
            except NotFoundError:
                console.print(f"[red]✗ Scan '{scan_id}' not found.[/red] Check the ID with [bold]sciath scan list[/bold]")
                raise typer.Exit(1)
            except SciathAPIError as exc:
                console.print(f"[red]✗ {exc}[/red]")
                raise typer.Exit(1)

            report_id = report_meta["id"]

            # 2. Poll until READY or FAILED
            p.update(task, description="Generating report…")
            for _ in range(_POLL_MAX):
                status_meta = api.get_report(report_id)
                if status_meta["status"] == "ready":
                    break
                if status_meta["status"] == "failed":
                    console.print(f"[red]✗ Report generation failed: {status_meta.get('error_message', '')}[/red]")
                    raise typer.Exit(1)
                time.sleep(_POLL_INTERVAL)
            else:
                console.print("[red]✗ Report timed out. Try again or check server logs.[/red]")
                raise typer.Exit(1)

            # 3. Download
            p.update(task, description="Downloading…")
            try:
                content, server_filename = api.download_report(report_id)
            except SciathAPIError as exc:
                console.print(f"[red]✗ {exc}[/red]")
                raise typer.Exit(1)

        # 4. Write to file
        ext = "pdf" if fmt == "pdf" else "json"
        out_path = Path(output) if output else Path(server_filename if server_filename != "report" else f"sciath_{scan_id[:8]}_{fmt}.{ext}")
        try:
            out_path.write_bytes(content)
        except IOError as exc:
            console.print(f"[red]✗ Could not write to {out_path}: {exc}[/red]")
            raise typer.Exit(1)

        size_kb = len(content) // 1024
        console.print(f"[green]✓ Saved to {out_path} ({size_kb} KB)[/green]")
