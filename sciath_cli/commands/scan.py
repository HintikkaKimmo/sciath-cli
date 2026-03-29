"""
Scan commands: scan (run), status, list.

DBOS async pipeline:
  - analyse/ returns immediately with {"status": "queued", "job_id": "..."}
  - CLI polls /{scan_id}/status/ until status ∈ {triage, complete, failed}
  - On failure: prints error_message from status response and exits 1

Output flow:
  scan result → OutputFormatter (format, explain, exit code threshold)
"""
import hashlib
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sciath_cli.api import SciathAPI, SciathAPIError, ServerError
from sciath_cli.config import requires_auth
from sciath_cli.console import console
from sciath_cli.output import OutputFormatter

app = typer.Typer(help="Run and manage vulnerability scans.")

# Poll status/ every N seconds; give up after _POLL_MAX attempts (~10 min ceiling)
_POLL_INTERVAL = 5
_POLL_MAX = 120

# Terminal statuses — stop polling when reached
_TERMINAL_STATUSES = {"triage", "complete", "failed", "superseded"}


@app.command("run")
@requires_auth
def run_scan(
    sbom: Optional[Path] = typer.Argument(None, help="Path to SBOM file (auto-detected if omitted)"),
    kconfig: Optional[Path] = typer.Option(None, "--kconfig", "-k", help="Kernel .config file"),
    dtb: Optional[Path] = typer.Option(None, "--dtb", "-d", help="Device Tree Blob file (.dts/.dtb)"),
    depgraph: Optional[Path] = typer.Option(None, "--depgraph", help="Bitbake dependency graph (dot format from bitbake -g)"),
    custom_filter: Optional[Path] = typer.Option(None, "--custom-filter", "-cf", help="Custom filter rules (JSON)"),
    policy: Optional[str] = typer.Option(None, "--policy", help="Named filter policy (server-side, replaces --custom-filter)"),
    yocto_machine: Optional[str] = typer.Option(None, "--yocto-machine", help="Yocto MACHINE variable"),
    yocto_distro: Optional[str] = typer.Option(None, "--yocto-distro", help="Yocto DISTRO variable"),
    kernel_version: Optional[str] = typer.Option(None, "--kernel-version", help="Kernel version string"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Version label (default: timestamp)"),
    project_id: Optional[str] = typer.Option(None, "--project", "-p", help="Project ID (overrides active project)"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, quiet"),
    explain: bool = typer.Option(False, "--explain", "-e", help="Show filter reasoning per CVE"),
    severity_threshold: str = typer.Option("", "--severity-threshold", help="Exit 1 if findings >= threshold (critical/high/medium/low)"),
    fail_on_kev: bool = typer.Option(False, "--fail-on-kev", help="Exit 1 if any CISA KEV finding is open"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip local cache, force fresh upload"),
    config: Any = None,
) -> None:
    """Run a vulnerability scan on a firmware SBOM."""
    # Auto-detect SBOM if not provided
    if sbom is None:
        sbom = _auto_detect_sbom()
        if sbom is None:
            raise typer.Exit(1)
    elif not sbom.exists():
        console.print(f"[red]✗ SBOM file not found: {sbom}[/red]")
        raise typer.Exit(1)

    # Auto-detect kconfig if not provided
    if kconfig is None:
        kconfig = _auto_detect_file([".config", "build/.config"])

    # Auto-detect DTB if not provided
    if dtb is None:
        dtb = _auto_detect_file_glob(["*.dts", "*.dtb"])

    # --policy and --custom-filter are mutually exclusive
    if policy and custom_filter:
        console.print("[red]✗ Cannot use both --policy and --custom-filter. Choose one.[/red]")
        raise typer.Exit(1)

    # Auto-detect custom filter if not provided (and no policy specified)
    if custom_filter is None and not policy:
        custom_filter = _auto_detect_file(["custom_filter.json"])

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
    dtb_raw = dtb.read_text(errors="replace") if dtb else ""
    depgraph_raw = depgraph.read_text(errors="replace") if depgraph else ""
    custom_filter_raw = custom_filter.read_text(errors="replace") if custom_filter else ""

    # Check local cache for matching inputs
    from sciath_cli import cache as _cache

    cached_scan_id = None
    if not no_cache:
        cached_scan_id = _cache.get_cached_scan(proj_id, sbom_raw, kconfig_raw, dtb_raw, custom_filter_raw)

    # Idempotency key: hash of project + version + sbom content
    idem_key = hashlib.sha256(f"{proj_id}:{version}:{sbom_raw}".encode()).hexdigest()[:32]

    formatter = OutputFormatter(
        format=output_format,
        explain=explain,
        severity_threshold=severity_threshold,
        fail_on_kev=fail_on_kev,
    )

    result: dict[str, Any] | None = None
    assessments: list[dict[str, Any]] | None = None

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("  Uploading artifacts...", total=None)

        with SciathAPI(config) as api:
            # Use cached scan if available
            if cached_scan_id:
                try:
                    result = api.get_scan_status(cached_scan_id)
                    if result.get("status") in _TERMINAL_STATUSES:
                        progress.update(task, description="  Using cached result...")
                        # Fetch assessments if needed
                        assessments = None
                        if explain or output_format == "json" or severity_threshold or fail_on_kev:
                            try:
                                resp = api.list_assessments(scan_id=cached_scan_id, limit=500)
                                assessments = resp.get("items", [])
                            except SciathAPIError:
                                pass
                        console.print("  [dim]Cache hit — using previous scan result[/dim]")
                        formatter.render_scan(result, assessments=assessments)
                        raise typer.Exit(formatter.exit_code)
                except SciathAPIError:
                    pass  # Cache miss — scan may have been deleted, proceed with upload

            try:
                scan = api.create_scan(
                    project_id=proj_id,
                    version_label=version,
                    sbom_raw=sbom_raw,
                    sbom_format=sbom_format,
                    kconfig_raw=kconfig_raw,
                    dtb_raw=dtb_raw,
                    depgraph_raw=depgraph_raw,
                    custom_filter_raw=custom_filter_raw if not policy else "",
                    policy_name=policy,
                    yocto_machine=yocto_machine or "",
                    yocto_distro=yocto_distro or "",
                    kernel_version=kernel_version or "",
                    idempotency_key=idem_key,
                )
            except SciathAPIError as exc:
                console.print(f"\n[red]✗ Failed to create scan: {exc}[/red]")
                raise typer.Exit(1)

            scan_id = scan["id"]
            progress.update(task, description="  Running analysis...")

            result = _run_analyse_with_retry(api, scan_id, progress, task)

            # Fetch assessments for explain/json/exit-code features
            assessments = None
            if result and (explain or output_format == "json" or severity_threshold or fail_on_kev):
                try:
                    resp = api.list_assessments(scan_id=scan_id, limit=500)
                    assessments = resp.get("items", [])
                except SciathAPIError:
                    pass  # Non-fatal — render without assessments

    if result is None:
        raise typer.Exit(1)

    # Save to local cache for future runs with same inputs
    _cache.save_cache(proj_id, sbom_raw, kconfig_raw, dtb_raw, str(result.get("id", "")), custom_filter_raw)

    formatter.render_scan(result, assessments=assessments)
    raise typer.Exit(formatter.exit_code)


def _resolve_scan_id(api: SciathAPI, scan_id: str) -> str:
    """Resolve a short scan ID prefix to a full UUID.

    If scan_id already looks like a full UUID (36 chars), return as-is.
    Otherwise, list recent scans and find one whose ID starts with the prefix.
    Raises typer.Exit on no match or ambiguous match.
    """
    if len(scan_id) >= 36:
        return scan_id

    try:
        result = api.list_scans(limit=100)
    except SciathAPIError:
        # Can't resolve, let the API try the raw value
        return scan_id

    matches = [s for s in result.get("items", []) if s["id"].startswith(scan_id)]

    if len(matches) == 1:
        resolved: str = matches[0]["id"]
        return resolved
    elif len(matches) == 0:
        console.print(f"[red]✗ No scan found matching prefix '{scan_id}'[/red]")
        raise typer.Exit(1)
    else:
        console.print(f"[red]✗ Ambiguous prefix '{scan_id}' matches {len(matches)} scans:[/red]")
        for m in matches[:5]:
            console.print(f"  {m['id'][:12]}  {m.get('version_label', '')}")
        console.print("[dim]Use a longer prefix or the full ID.[/dim]")
        raise typer.Exit(1)


def _run_analyse_with_retry(api: SciathAPI, scan_id: str, progress: Any, task: Any) -> Optional[dict[str, Any]]:
    """
    Dispatch analysis then poll until a terminal status is reached.

    DBOS async contract:
      1. POST analyse/ → returns immediately with {"status": "queued"}
      2. Poll GET status/ every _POLL_INTERVAL seconds
      3. Return status dict when status ∈ _TERMINAL_STATUSES
      4. Return None on failure (caller exits 1)
    """
    # Step 1: dispatch
    try:
        api.trigger_analyse(scan_id)
    except ServerError as exc:
        console.print(f"\n[red]✗ Failed to dispatch analysis: {exc}[/red]")
        console.print(
            f"  Scan ID: [bold]{scan_id}[/bold]\n"
            f"  Retry with: [dim]sciath scan reanalyse {scan_id[:8]}[/dim]"
        )
        return None
    except SciathAPIError as exc:
        console.print(f"\n[red]✗ Analysis failed: {exc}[/red]")
        console.print(f"  Scan ID: [bold]{scan_id}[/bold]")
        return None

    # Step 2: poll until terminal
    progress.update(task, description="  Analysing (polling status)...")
    for poll_n in range(_POLL_MAX):
        time.sleep(_POLL_INTERVAL)
        try:
            data = api.get_scan_status(scan_id)
        except SciathAPIError as exc:
            console.print(f"\n[red]✗ Status poll failed: {exc}[/red]")
            return None

        status = data.get("status", "")
        progress.update(task, description=f"  Analysing... [{status}]")

        if status in _TERMINAL_STATUSES:
            if status == "failed":
                error = data.get("error_message") or "unknown pipeline error"
                console.print(f"\n[red]✗ Analysis failed: {error}[/red]")
                console.print(
                    f"  Scan ID: [bold]{scan_id}[/bold]\n"
                    f"  Retry with: [dim]sciath scan reanalyse {scan_id[:8]}[/dim]"
                )
                return None
            return data

    console.print(
        f"\n[yellow]⚠ Timed out waiting for analysis ({_POLL_MAX * _POLL_INTERVAL}s).[/yellow]\n"
        f"  The worker may still be running. Check with: [dim]sciath scan status {scan_id[:8]}[/dim]"
    )
    return None


@app.command()
@requires_auth
def reanalyse(
    scan_id: str = typer.Argument(..., help="Scan ID or prefix"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, quiet"),
    config: Any = None,
) -> None:
    """Re-run analysis on an existing scan (e.g. after a previous failure)."""
    formatter = OutputFormatter(format=output_format)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("  Running analysis...", total=None)
        with SciathAPI(config) as api:
            scan_id = _resolve_scan_id(api, scan_id)
            result = _run_analyse_with_retry(api, scan_id, progress, task)

    if result is None:
        raise typer.Exit(1)

    formatter.render_scan(result)
    raise typer.Exit(formatter.exit_code)


@app.command()
@requires_auth
def status(
    scan_id: str = typer.Argument(..., help="Scan ID or prefix"),
    config: Any = None,
) -> None:
    """Check the status of a scan."""
    with SciathAPI(config) as api:
        scan_id = _resolve_scan_id(api, scan_id)
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
    config: Any = None,
) -> None:
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
    table.add_column("Remaining", justify="right")
    table.add_column("ID", style="dim")

    for s in items:
        total = s.get("total_vulnerabilities", 0)
        suppressed = s.get("suppressed_count", 0)
        remaining = s.get("remaining_count", total - suppressed)
        table.add_row(
            s.get("version_label", ""),
            s.get("status", ""),
            str(s.get("total_components", 0)),
            str(total),
            str(suppressed),
            str(remaining),
            s["id"][:8],
        )

    console.print(table)


# ── Auto-detection ──────────────────────────────────────────────────────────

_SBOM_CANDIDATES = [
    "sbom.json", "bom.json", "sbom.xml", "bom.xml",
    "sbom.cdx.json", "sbom.spdx.json",
]

_SBOM_GLOBS = [
    "build/tmp/deploy/*/sbom-*.json",
]


def _auto_detect_sbom() -> Optional[Path]:
    """Auto-discover SBOM file in the current directory."""
    from pathlib import Path as P
    cwd = P.cwd()

    # Check named candidates
    for name in _SBOM_CANDIDATES:
        candidate = cwd / name
        if candidate.exists():
            console.print(f"  [dim]Auto-detected SBOM: {candidate.name}[/dim]")
            return candidate

    # Check glob patterns
    import glob
    for pattern in _SBOM_GLOBS:
        matches = sorted(glob.glob(str(cwd / pattern)))
        if matches:
            found = P(matches[0])
            console.print(f"  [dim]Auto-detected SBOM: {found.relative_to(cwd)}[/dim]")
            if len(matches) > 1:
                console.print(f"  [yellow]⚠ Found {len(matches)} SBOMs — using first. Specify path to override.[/yellow]")
            return found

    console.print("[red]✗ No SBOM file found.[/red] Checked:")
    for name in _SBOM_CANDIDATES:
        console.print(f"  [dim]{name}[/dim]")
    for pattern in _SBOM_GLOBS:
        console.print(f"  [dim]{pattern}[/dim]")
    console.print("\nSpecify the SBOM path: [bold]sciath scan run <path>[/bold]")
    return None


def _auto_detect_file(candidates: list[str]) -> Optional[Path]:
    """Check a list of relative paths, return first that exists."""
    from pathlib import Path as P
    for name in candidates:
        candidate = P.cwd() / name
        if candidate.exists():
            console.print(f"  [dim]Auto-detected: {name}[/dim]")
            return candidate
    return None


def _auto_detect_file_glob(patterns: list[str]) -> Optional[Path]:
    """Check glob patterns in cwd, return first match."""
    import glob
    from pathlib import Path as P
    for pattern in patterns:
        matches = sorted(glob.glob(str(P.cwd() / pattern)))
        if matches:
            found = P(matches[0])
            console.print(f"  [dim]Auto-detected: {found.name}[/dim]")
            return found
    return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _quality_grade(score: float) -> str:
    """Convert a 0.0-1.0 quality score to a letter grade."""
    if score >= 0.9:
        return "A"
    if score >= 0.8:
        return "B"
    if score >= 0.7:
        return "C"
    if score >= 0.6:
        return "D"
    return "F"


def _detect_format(path: Path, raw: str) -> str:
    """Heuristic SBOM format detection from filename + content."""
    name = path.name.lower()
    if "spdx" in name or raw.strip().startswith('{"SPDXID"') or '"spdxVersion"' in raw:
        return "spdx"
    if "yocto" in name or name.endswith(".manifest"):
        return "yocto_manifest"
    return "cyclonedx"


def _display_scan_summary(data: dict[str, Any]) -> None:
    total = data.get("total_vulnerabilities", 0)
    suppressed = data.get("suppressed_count", 0)
    remaining = data.get("remaining_count", total - suppressed)
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

    quality = data.get("sbom_quality_score")
    if quality is not None:
        grade = _quality_grade(quality)
        table.add_row("SBOM Quality:", f"{quality:.0%} ({grade})")

    console.print()
    console.print(table)
    console.print()

    if remaining > 0:
        scan_short = str(data.get("id", ""))[:8]
        console.print("  Next steps:")
        console.print(f"    [dim]sciath assess list {scan_short}[/dim]   # Review CVEs")
        console.print(f"    [dim]sciath report {scan_short}[/dim]        # Generate Article 13 report")
    console.print()
