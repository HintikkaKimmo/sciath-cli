"""vex — direct CycloneDX export from the CLI."""
from pathlib import Path
from typing import Optional

import typer

from sciath_cli.config import requires_auth
from sciath_cli.console import console

app = typer.Typer(help="Export CycloneDX SBOM or VEX documents directly (no report record created).")

_VALID_FORMATS = {"vex_cdx", "sbom_cdx", "sbom_vex_cdx", "sarif"}


@app.command()
@requires_auth
def vex(
    scan_id: str = typer.Argument(..., help="Scan ID to export"),
    fmt: str = typer.Option("vex_cdx", "--format", "-f",
                             help="Format: vex_cdx | sbom_cdx | sbom_vex_cdx"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    validate: bool = typer.Option(False, "--validate",
                                  help="Validate output against CycloneDX 1.5 schema"),
    config=None,
):
    """
    Export a CycloneDX document directly (no report record created).

    Faster than 'sciath report' — returns JSON immediately without going through
    the GENERATING→READY lifecycle. Use for CI pipelines.
    """
    from sciath_cli.api import NotFoundError, SciathAPI, SciathAPIError, ValidationError

    if fmt not in _VALID_FORMATS:
        console.print(f"[red]✗ Unknown format '{fmt}'. Choose: {', '.join(sorted(_VALID_FORMATS))}[/red]")
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        try:
            content = api.export_cdx(scan_id, fmt=fmt, validate=validate)
        except NotFoundError:
            console.print("[red]✗ Scan not found.[/red]")
            raise typer.Exit(1)
        except ValidationError as exc:
            console.print(f"[red]✗ Validation error: {exc}[/red]")
            raise typer.Exit(1)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    out_path = Path(output) if output else Path(f"sciath_{scan_id[:8]}_{fmt}.json")
    try:
        out_path.write_bytes(content)
    except IOError as exc:
        console.print(f"[red]✗ Could not write to {out_path}: {exc}[/red]")
        raise typer.Exit(1)

    size_kb = len(content) // 1024
    console.print(f"[green]✓ Saved {fmt} to {out_path} ({size_kb} KB)[/green]")
