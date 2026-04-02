"""
Shared output formatter for all CLI commands.

Handles format selection (table/json/quiet), explain mode (filter reasoning),
and policy-driven exit codes (severity threshold, KEV gating).

Architecture:
  scan result → OutputFormatter
                  ├── format=table   (TTY default: Rich tables + explain rows)
                  ├── format=json    (composable JSON with summary + reasoning)
                  ├── format=quiet   (exit code only, errors to stderr)
                  └── exit_code ← severity threshold check (independent of format)
"""

import json
import sys
from dataclasses import dataclass
from typing import Any

from rich.table import Table

from sciath_cli.console import console

# Human-readable names for filter layers in waterfall display
_LAYER_DISPLAY_NAMES = {
    "build_time": "build-time filter",
    "kconfig": "Kconfig suppression",
    "dtb": "DTB device tree filter",
    "packageconfig": "PACKAGECONFIG filter",
    "busybox": "busybox applet filter",
    "patch": "patch detection",
    "custom": "custom policy rules",
    "deployment": "deployment context",
}


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


@dataclass
class OutputFormatter:
    """
    Unified output for scan results.

    Usage:
        fmt = OutputFormatter(format="table", explain=True, severity_threshold="critical")
        fmt.render_scan(result, assessments=assessments)
        raise typer.Exit(fmt.exit_code)
    """

    format: str = "table"  # table, json, quiet
    explain: bool = False
    severity_threshold: str = ""  # critical, high, medium, low
    fail_on_kev: bool = False
    exit_code: int = 0

    def render_scan(self, data: dict[str, Any], assessments: list[dict[str, Any]] | None = None) -> None:
        """Render scan results in the chosen format."""
        if self.format == "quiet":
            self._compute_exit_code(data, assessments)
            return

        if self.format == "json":
            self._render_json(data, assessments)
        else:
            self._render_table(data, assessments)

        self._compute_exit_code(data, assessments)

    def _compute_exit_code(self, data: dict[str, Any], assessments: list[dict[str, Any]] | None) -> None:
        """Set exit_code based on severity threshold and KEV policy."""
        if not self.severity_threshold and not self.fail_on_kev:
            return

        if not assessments:
            return

        threshold_map = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
        min_score = threshold_map.get(self.severity_threshold, 0.0)

        if self.severity_threshold:
            for a in assessments:
                score = a.get("vulnerability", {}).get("cvss_score") or 0
                status = a.get("status", "")
                if score >= min_score and status not in ("not_affected", "fixed"):
                    self.exit_code = 1
                    return

        if self.fail_on_kev:
            for a in assessments:
                if a.get("vulnerability", {}).get("is_kev"):
                    status = a.get("status", "")
                    if status not in ("not_affected", "fixed"):
                        self.exit_code = 1
                        return

    def _render_table(self, data: dict[str, Any], assessments: list[dict[str, Any]] | None) -> None:
        """Rich table output for TTY."""
        total = data.get("total_vulnerabilities", 0)
        suppressed = data.get("suppressed_count", 0)
        remaining = data.get("remaining_count", total - suppressed)
        pct = round(suppressed / total * 100) if total > 0 else 0

        table = Table(title="SCAN SUMMARY", box=None, show_header=False, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", style="bold")

        table.add_row("Components:", str(data.get("total_components", 0)))
        table.add_row("CVEs Matched:", f"[bold]{total}[/bold]")
        table.add_row("Suppressed:", f"[green]{suppressed}[/green]  ({pct}%)")
        remaining_style = "bold red" if remaining > 0 else "bold green"
        table.add_row("Remaining:", f"[{remaining_style}]{remaining}[/{remaining_style}]")
        table.add_row("Status:", data.get("status", "").upper())
        table.add_row("Version:", data.get("version_label", ""))
        table.add_row("Scan ID:", str(data.get("id", ""))[:8])

        quality = data.get("sbom_quality_score")
        if quality is not None:
            grade = _quality_grade(quality)
            table.add_row("SBOM Quality:", f"{quality:.0%} ({grade})")

        console.print()
        console.print(table)

        funnel = data.get("suppression_funnel")
        if funnel and funnel.get("layers"):
            self._render_waterfall(funnel, data)

        if self.explain and assessments:
            self._render_explain_table(assessments)

        console.print()
        if remaining > 0:
            scan_short = str(data.get("id", ""))[:8]
            console.print("  Next steps:")
            console.print(f"    [dim]sciath assess list {scan_short}[/dim]   # Review CVEs")
            console.print(f"    [dim]sciath report {scan_short}[/dim]        # Generate Article 13 report")
        console.print()

    def _render_waterfall(self, funnel: dict[str, Any], data: dict[str, Any]) -> None:
        """Render the suppression funnel as a waterfall — the 'shareable screenshot'."""
        raw = funnel.get("raw", 0)
        if raw == 0:
            return

        machine = data.get("yocto_machine") or ""
        distro = data.get("yocto_distro") or ""
        version = data.get("version_label") or ""
        project = data.get("project_name") or ""

        header_parts = [p for p in [project, version, distro, machine] if p]
        header = f"  Scan Results: {' / '.join(header_parts)}" if header_parts else "  Scan Results"

        console.print()
        console.print(header, style="bold")
        console.print("  " + "=" * 56)

        # Raw count
        console.print(f"    Raw CVEs from SBOM:            [bold]{raw:>5}[/bold]")

        # Each layer
        for layer in funnel.get("layers", []):
            name = layer.get("name", "")
            suppressed = layer.get("suppressed", 0)
            remaining = layer.get("remaining", 0)
            label = layer.get("label", "")

            # Format the layer display name
            display_name = _LAYER_DISPLAY_NAMES.get(name, name)

            if suppressed > 0:
                delta = f"(-{suppressed} {label})"
                console.print(f"    After {display_name + ':':<28} [bold]{remaining:>5}[/bold]  [green]{delta}[/green]")
            elif "skipped" in label:
                console.print(f"    After {display_name + ':':<28} [dim]{remaining:>5}  ({label})[/dim]")
            # Layers with 0 suppressed and artifact present ("no matches") are omitted for cleanliness

        console.print("  " + "=" * 56)

        action = funnel.get("action_required", 0)
        if action == 0:
            console.print(f"    ACTION REQUIRED:               [bold green]{action:>5}  ✓[/bold green]")
        else:
            console.print(f"    ACTION REQUIRED:               [bold]{action:>5}[/bold]")

        # Severity breakdown from assessments if available — shown inline
        # This requires assessment data we may not have; skip if not in data
        severity_counts = data.get("severity_counts")
        if severity_counts:
            for level, count in severity_counts.items():
                if count > 0:
                    style = "bold red" if level in ("critical", "kev") else ""
                    marker = "  <<<" if level in ("critical", "kev") else ""
                    console.print(f"      {level.capitalize():<30} {count:>5}{marker}", style=style)

    def _render_explain_table(self, assessments: list[dict[str, Any]]) -> None:
        """Show filter reasoning for suppressed CVEs and why survivors matter."""
        # --- Suppressed CVEs ---
        suppressed = [a for a in assessments if a.get("filter_layer") and a["filter_layer"] != "none"]
        if suppressed:
            console.print()
            table = Table(title="FILTER REASONING", box=None, show_header=True, padding=(0, 1))
            table.add_column("CVE", style="bold")
            table.add_column("Layer", style="dim")
            table.add_column("Status")
            table.add_column("Rationale")

            for a in suppressed:
                vuln = a.get("vulnerability", {})
                status = a.get("status", "")
                color = "green" if status == "not_affected" else "red" if status == "affected" else "yellow"
                reason = (
                    a.get("suppression_rationale")
                    or a.get("justification_text")
                    or a.get("justification_category")
                    or "—"
                )
                table.add_row(
                    vuln.get("vuln_id", ""),
                    a.get("filter_layer", ""),
                    f"[{color}]{status}[/{color}]",
                    reason[:100],
                )

            console.print(table)

        # --- Surviving CVEs (why they matter) ---
        survivors = [
            a for a in assessments
            if a.get("status") in ("affected", "under_investigation")
        ]
        if not survivors:
            return

        # Sort by CVSS descending, KEV first
        survivors.sort(
            key=lambda a: (
                not a.get("vulnerability", {}).get("is_kev", False),
                -(a.get("vulnerability", {}).get("cvss_score") or 0),
            )
        )

        console.print()
        table = Table(title="WHY THESE CVEs MATTER", box=None, show_header=True, padding=(0, 1))
        table.add_column("CVE", style="bold")
        table.add_column("Component")
        table.add_column("CVSS")
        table.add_column("EPSS")
        table.add_column("Flags", style="dim")
        table.add_column("Why it survived")

        for a in survivors[:30]:  # Cap at 30 to avoid overwhelming output
            vuln = a.get("vulnerability", {})
            cvss = vuln.get("cvss_score")
            epss = vuln.get("epss_score")
            is_kev = vuln.get("is_kev", False)
            component = vuln.get("component", {}).get("name", "")

            cvss_str = f"{cvss:.1f}" if cvss is not None else "—"
            epss_str = f"{epss:.2f}" if epss is not None and epss > 0 else "—"
            cvss_style = "bold red" if cvss and cvss >= 9.0 else "bold yellow" if cvss and cvss >= 7.0 else ""

            flags = []
            if is_kev:
                flags.append("[red]KEV[/red]")
            if cvss and cvss >= 9.0:
                flags.append("[red]Critical[/red]")

            survival = a.get("survival_rationale") or "No filter matched"

            table.add_row(
                vuln.get("vuln_id", ""),
                component[:20],
                f"[{cvss_style}]{cvss_str}[/{cvss_style}]" if cvss_style else cvss_str,
                epss_str,
                " ".join(flags) if flags else "—",
                survival[:80],
            )

        console.print(table)

        if len(survivors) > 30:
            console.print(f"  [dim]... and {len(survivors) - 30} more[/dim]")

    def _render_json(self, data: dict[str, Any], assessments: list[dict[str, Any]] | None) -> None:
        """Composable JSON output with summary and optional reasoning."""
        total = data.get("total_vulnerabilities", 0)
        suppressed = data.get("suppressed_count", 0)
        remaining = data.get("remaining_count", total - suppressed)

        output: dict[str, Any] = {
            "summary": (
                f"{remaining} open CVEs out of {total} total. "
                f"{suppressed} suppressed ({round(suppressed / total * 100) if total else 0}%). "
                f"Status: {data.get('status', 'unknown')}."
            ),
            "scan_id": data.get("id", ""),
            "version": data.get("version_label", ""),
            "status": data.get("status", ""),
            "total_components": data.get("total_components", 0),
            "total_vulnerabilities": total,
            "suppressed_count": suppressed,
            "remaining_count": remaining,
            "analysed_at": data.get("analysed_at", ""),
        }

        quality = data.get("sbom_quality_score")
        if quality is not None:
            output["sbom_quality_score"] = quality

        funnel = data.get("suppression_funnel")
        if funnel:
            output["suppression_funnel"] = funnel

        if assessments:
            output["assessments"] = [
                {
                    "cve_id": a.get("vulnerability", {}).get("vuln_id", ""),
                    "cvss": a.get("vulnerability", {}).get("cvss_score"),
                    "epss_score": a.get("vulnerability", {}).get("epss_score"),
                    "is_kev": a.get("vulnerability", {}).get("is_kev", False),
                    "matched_sources": a.get("vulnerability", {}).get("matched_sources", []),
                    "confidence_tier": a.get("vulnerability", {}).get("confidence_tier", ""),
                    "component": a.get("vulnerability", {}).get("component", {}).get("name", ""),
                    "status": a.get("status", ""),
                    "filter_layer": a.get("filter_layer", ""),
                    "applied_filter_layers": a.get("applied_filter_layers", []),
                    "justification": a.get("justification_text", ""),
                    "suppression_rationale": a.get("suppression_rationale", ""),
                    "survival_rationale": a.get("survival_rationale", ""),
                    "confidence": a.get("confidence", ""),
                    "contextual_cvss": a.get("contextual_cvss"),
                }
                for a in assessments
            ]

        # Use sys.stdout for clean JSON (no Rich markup) when piped
        sys.stdout.write(json.dumps(output, indent=2) + "\n")


# ============================================================
# CRA Readiness renderer (standalone, not tied to OutputFormatter)
# ============================================================

_STATUS_ICONS = {
    "passed": "[green]✓[/green]",
    "failed": "[red]✗[/red]",
    "warning": "[yellow]![/yellow]",
    "out_of_scope": "[dim]–[/dim]",
    "pending": "[dim]…[/dim]",
}

_VERDICT_STYLES = {
    "shippable": ("bold green", "SHIPPABLE ✓"),
    "not_ready": ("bold red", "NOT READY"),
    "incomplete": ("bold yellow", "INCOMPLETE"),
    "pending": ("bold yellow", "PENDING"),
}


def render_cra_readiness(data: dict[str, Any], output_format: str = "table") -> None:
    """Render CRA readiness verdict. Works with both table and json formats."""
    if output_format == "json":
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return

    if output_format == "quiet":
        return

    verdict = data.get("verdict", "unknown")
    percentage = data.get("percentage", 0)
    checklist = data.get("checklist", [])
    blockers = data.get("blockers", [])

    style, label = _VERDICT_STYLES.get(verdict, ("bold", verdict.upper()))

    # Progress bar
    filled = int(percentage / 5)  # 20 chars total
    bar = "█" * filled + "░" * (20 - filled)

    console.print()
    console.print(f"  CRA READINESS: [{style}]{label}[/{style}]")
    console.print(f"  {bar}  {percentage:.0f}% compliant")
    console.print()

    # Checklist
    for item in checklist:
        icon = _STATUS_ICONS.get(item.get("status", ""), " ")
        req = item.get("requirement", "")
        article = item.get("article", "")
        detail = item.get("detail", "")

        if item.get("status") == "out_of_scope":
            console.print(f"  {icon} [dim]{req} ({article}) — {detail}[/dim]")
        else:
            console.print(f"  {icon} {req} [dim]({article})[/dim]")
            if detail:
                console.print(f"      [dim]{detail}[/dim]")

    # Blockers summary
    if blockers:
        console.print()
        console.print("  [bold red]Blockers:[/bold red]")
        for b in blockers:
            console.print(f"    [red]✗ {b}[/red]")

    console.print()
