"""
Assessment commands: list, approve, reject.
"""
from typing import Any, Optional

import typer
from rich.table import Table

from sciath_cli.api import SciathAPI, SciathAPIError
from sciath_cli.config import requires_auth
from sciath_cli.console import console

app = typer.Typer(help="Review vulnerability assessments.")


@app.command("list")
@requires_auth
def list_assessments(
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID or prefix to filter by"),
    pending_only: bool = typer.Option(True, "--pending/--all", help="Show only assessments needing review"),
    filter_layer: Optional[str] = typer.Option(None, "--filter-layer", help="Filter by layer (kconfig/dtb/busybox/packageconfig/patch/custom/build_time/deployment)"),
    config: Any = None,
) -> None:
    """List vulnerability assessments for a scan."""
    with SciathAPI(config) as api:
        try:
            result = api.list_assessments(
                scan_id=scan_id,
                status="auto_pending" if pending_only else None,
                filter_layer=filter_layer,
            )
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    if not items:
        console.print("[dim]No assessments found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("CVE ID")
    table.add_column("CVSS", justify="right")
    table.add_column("Status")
    table.add_column("Filter Layer")
    table.add_column("Confidence")
    table.add_column("EPSS", justify="right")
    table.add_column("Sources")
    table.add_column("ID", style="dim")

    for a in items:
        vuln = a.get("vulnerability") or {}
        cvss = vuln.get("cvss_score")
        epss = vuln.get("epss_score")
        tier = vuln.get("confidence_tier", "")
        table.add_row(
            vuln.get("vuln_id", a.get("vuln_id", "")),
            f"{cvss:.1f}" if cvss is not None else "",
            a.get("status", ""),
            a.get("filter_layer", ""),
            str(a.get("confidence", "")),
            f"{epss:.0%}" if epss is not None else "",
            tier,
            a["id"][:8],
        )

    console.print(table)
    total = result.get("total", len(items))
    console.print(f"[dim]{total} assessment(s)[/dim]")


@app.command()
@requires_auth
def approve(
    assessment_id: str = typer.Argument(..., help="Assessment ID or prefix"),
    note: Optional[str] = typer.Option(None, "--note", "-n", help="Optional review note"),
    config: Any = None,
) -> None:
    """Approve an assessment (confirm CVE is not applicable)."""
    with SciathAPI(config) as api:
        try:
            api.update_assessment(assessment_id, {"review_status": "approved", "review_note": note or ""})
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    console.print(f"[green]✓[/green] Assessment [bold]{assessment_id[:8]}[/bold] approved")


@app.command()
@requires_auth
def reject(
    assessment_id: str = typer.Argument(..., help="Assessment ID or prefix"),
    note: Optional[str] = typer.Option(None, "--note", "-n", help="Reason for rejection"),
    config: Any = None,
) -> None:
    """Reject an assessment (flag CVE for manual review)."""
    with SciathAPI(config) as api:
        try:
            api.update_assessment(assessment_id, {"review_status": "rejected", "review_note": note or ""})
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    console.print(f"[yellow]✗[/yellow] Assessment [bold]{assessment_id[:8]}[/bold] flagged for review")
