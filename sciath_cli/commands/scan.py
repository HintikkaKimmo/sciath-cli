"""
Scan commands: scan (run), status, list.

Retry logic for analyse/:
  - Up to 3 attempts with exponential backoff (2s, 4s, 8s)
  - On all failures, prints scan ID so user can retry manually
  - Designed to be transparently replaced by DBOS polling (P2-005)
    once async analysis lands: analyse/ returns 202 and CLI polls status/
"""
import hashlib
import time
from pathlib import Path
from typing import Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sciath_cli.api import SciathAPI, SciathAPIError, ServerError
from sciath_cli.config import requires_auth
from sciath_cli.console import console

app = typer.Typer(help="Run and manage vulnerability scans.")

_MAX_ANALYSE_RETRIES = 3
_ANALYSE_BACKOFF = [2, 4, 8]  # seconds between retries


@app.command("run")
@requires_auth
def run_scan(
    sbom: Path = typer.Argument(..., help="Path to SBOM file (CycloneDX JSON/XML, SPDX JSON, Yocto manifest)"),
    kconfig: Optional[Path] = typer.Option(None, "--kconfig", "-k", help="Kernel .config file"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Version label (default: timestamp)"),
    project_id: Optional[str] = typer.Option(None, "--project", "-p", help="Project ID (overrides active project)"),
    output_json: bool = typer.Option(False, "--json", help="Output result as JSON"),
    config=None,
):
    """Run a vulnerability scan on a firmware SBOM."""
    if not sbom.exists():
        console.print(f"[red]✗ SBOM file not found: {sbom}[/red]")
        raise typer.Exit(1)

    proj_id = project_id or config.active_project_id
    if not proj_id:
        console.print(
            "[red]✗ No project selected.[/red] "
            "Run [bold]sciath project select <name>[/bold] or pass [bold]--project <id>[/bold]."
        )
        raise typer.Exit(1)

    if not version:
        version = f"cli-{int(time.time())}"

    sbom_raw = sbom.read_text(errors="replace")
    sbom_format = _detect_format(sbom, sbom_raw)
    kconfig_raw = kconfig.read_text(errors="replace") if kconfig else ""

    # Idempotency key: hash of project + version + sbom content
    idem_key = hashlib.sha256(f"{proj_id}:{version}:{sbom_raw[:500]}".encode()).hexdigest()[:32]

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("  Uploading artifacts...", total=None)

        with SciathAPI(config) as api:
            try:
                scan = api.create_scan(
                    project_id=proj_id,
                    version_label=version,
                    sbom_raw=sbom_raw,
                    sbom_format=sbom_format,
                    kconfig_raw=kconfig_raw,
                    idempotency_key=idem_key,
                )
            except SciathAPIError as exc:
                console.print(f"\n[red]✗ Failed to create scan: {exc}[/red]")
                raise typer.Exit(1)

            scan_id = scan["id"]
            progress.update(task, description="  Running analysis...")

            result = _run_analyse_with_retry(api, scan_id, progress, task)

    if result is None:
        raise typer.Exit(1)

    if output_json:
        import json
        console.print_json(json.dumps(result))
    else:
        _display_scan_summary(result)


def _run_analyse_with_retry(api: SciathAPI, scan_id: str, progress, task) -> Optional[dict]:
    """
    Call analyse/ with exponential backoff retry on server errors.
    Returns the status dict on success, None on exhausted retries.
    """
    for attempt, wait in enumerate(_ANALYSE_BACKOFF, start=1):
        try:
            api.trigger_analyse(scan_id)
            return api.get_scan_status(scan_id)
        except ServerError as exc:
            if attempt < _MAX_ANALYSE_RETRIES:
                progress.update(
                    task,
                    description=f"  Server error, retrying ({attempt}/{_MAX_ANALYSE_RETRIES - 1})...",
                )
                time.sleep(wait)
            else:
                console.print(
                    f"\n[red]✗ Analysis failed after {_MAX_ANALYSE_RETRIES} attempts: {exc}[/red]"
                )
                console.print(
                    f"  Scan ID: [bold]{scan_id}[/bold]\n"
                    f"  Retry with: [dim]sciath scan reanalyse {scan_id[:8]}[/dim]"
                )
                return None
        except SciathAPIError as exc:
            console.print(f"\n[red]✗ Analysis failed: {exc}[/red]")
            console.print(f"  Scan ID: [bold]{scan_id}[/bold]")
            return None

    return None  # unreachable but satisfies type checker


@app.command()
@requires_auth
def reanalyse(
    scan_id: str = typer.Argument(..., help="Scan ID or prefix"),
    output_json: bool = typer.Option(False, "--json", help="Output result as JSON"),
    config=None,
):
    """Re-run analysis on an existing scan (e.g. after a previous failure)."""
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("  Running analysis...", total=None)
        with SciathAPI(config) as api:
            result = _run_analyse_with_retry(api, scan_id, progress, task)

    if result is None:
        raise typer.Exit(1)

    if output_json:
        import json
        console.print_json(json.dumps(result))
    else:
        _display_scan_summary(result)


@app.command()
@requires_auth
def status(
    scan_id: str = typer.Argument(..., help="Scan ID or prefix"),
    config=None,
):
    """Check the status of a scan."""
    with SciathAPI(config) as api:
        try:
            data = api.get_scan_status(scan_id)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    _display_scan_summary(data)


@app.command("list")
@requires_auth
def list_scans(
    project_id: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    config=None,
):
    """List recent scans."""
    proj_id = project_id or config.active_project_id

    with SciathAPI(config) as api:
        try:
            result = api.list_scans(project_id=proj_id)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    if not items:
        console.print("[dim]No scans found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Version")
    table.add_column("Status")
    table.add_column("Components", justify="right")
    table.add_column("CVEs", justify="right")
    table.add_column("Suppressed", justify="right")
    table.add_column("ID", style="dim")

    for s in items:
        table.add_row(
            s.get("version_label", ""),
            s.get("status", ""),
            str(s.get("total_components", 0)),
            str(s.get("total_vulnerabilities", 0)),
            str(s.get("suppressed_count", 0)),
            s["id"][:8],
        )

    console.print(table)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _detect_format(path: Path, raw: str) -> str:
    """Heuristic SBOM format detection from filename + content."""
    name = path.name.lower()
    if "spdx" in name or raw.strip().startswith('{"SPDXID"') or '"spdxVersion"' in raw:
        return "spdx"
    if "yocto" in name or name.endswith(".manifest"):
        return "yocto_manifest"
    return "cyclonedx"


def _display_scan_summary(data: dict) -> None:
    total = data.get("total_vulnerabilities", 0)
    suppressed = data.get("suppressed_count", 0)
    remaining = total - suppressed
    pct = round(suppressed / total * 100) if total > 0 else 0

    table = Table(title="SCAN SUMMARY", box=None, show_header=False, padding=(0, 2))
    table.add_column("Label", style="dim")
    table.add_column("Value", style="bold")

    table.add_row("Components:", str(data.get("total_components", 0)))
    table.add_row("CVEs Matched:", str(total))
    table.add_row("Suppressed:", f"{suppressed}  ({pct}%)")
    table.add_row("Remaining:", str(remaining))
    table.add_row("Status:", data.get("status", "").upper())
    table.add_row("Version:", data.get("version_label", ""))
    table.add_row("Scan ID:", str(data.get("id", ""))[:8])

    console.print()
    console.print(table)
    console.print()

    if remaining > 0:
        scan_short = str(data.get("id", ""))[:8]
        console.print("  Next steps:")
        console.print(f"    [dim]sciath assess list {scan_short}[/dim]   # Review CVEs")
        console.print(f"    [dim]sciath report {scan_short}[/dim]        # Generate Article 13 report")
    console.print()
