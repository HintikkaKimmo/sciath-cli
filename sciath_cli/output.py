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

from rich.table import Table

from sciath_cli.console import console


@dataclass
class OutputFormatter:
    """
    Unified output for scan results.

    Usage:
        fmt = OutputFormatter(format="table", explain=True, severity_threshold="critical")
        fmt.render_scan(result, assessments=assessments)
        sys.exit(fmt.exit_code)
    """

    format: str = "table"  # table, json, quiet
    explain: bool = False
    severity_threshold: str = ""  # critical, high, medium, low
    fail_on_kev: bool = False
    exit_code: int = 0

    def render_scan(self, data: dict, assessments: list | None = None) -> None:
        """Render scan results in the chosen format."""
        if self.format == "quiet":
            self._compute_exit_code(data, assessments)
            return

        if self.format == "json":
            self._render_json(data, assessments)
        else:
            self._render_table(data, assessments)

        self._compute_exit_code(data, assessments)

    def _compute_exit_code(self, data: dict, assessments: list | None) -> None:
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

    def _render_table(self, data: dict, assessments: list | None) -> None:
        """Rich table output for TTY."""
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

        if self.explain and assessments:
            self._render_explain_table(assessments)

        console.print()
        if remaining > 0:
            scan_short = str(data.get("id", ""))[:8]
            console.print("  Next steps:")
            console.print(f"    [dim]sciath assess list {scan_short}[/dim]   # Review CVEs")
            console.print(f"    [dim]sciath report {scan_short}[/dim]        # Generate Article 13 report")
        console.print()

    def _render_explain_table(self, assessments: list) -> None:
        """Show filter reasoning for each assessment."""
        filtered = [a for a in assessments if a.get("filter_layer") and a["filter_layer"] != "none"]
        if not filtered:
            return

        console.print()
        table = Table(title="FILTER REASONING", box=None, show_header=True, padding=(0, 1))
        table.add_column("CVE", style="bold")
        table.add_column("Layer", style="dim")
        table.add_column("Status")
        table.add_column("Reason")

        for a in filtered:
            vuln = a.get("vulnerability", {})
            status = a.get("status", "")
            color = "green" if status == "not_affected" else "red" if status == "affected" else "yellow"
            table.add_row(
                vuln.get("vuln_id", ""),
                a.get("filter_layer", ""),
                f"[{color}]{status}[/{color}]",
                (a.get("justification_text") or a.get("justification_category") or "—")[:80],
            )

        console.print(table)

    def _render_json(self, data: dict, assessments: list | None) -> None:
        """Composable JSON output with summary and optional reasoning."""
        total = data.get("total_vulnerabilities", 0)
        suppressed = data.get("suppressed_count", 0)
        remaining = total - suppressed

        output = {
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

        if assessments:
            output["assessments"] = [
                {
                    "cve_id": a.get("vulnerability", {}).get("vuln_id", ""),
                    "cvss": a.get("vulnerability", {}).get("cvss_score"),
                    "is_kev": a.get("vulnerability", {}).get("is_kev", False),
                    "component": a.get("vulnerability", {}).get("component", {}).get("name", ""),
                    "status": a.get("status", ""),
                    "filter_layer": a.get("filter_layer", ""),
                    "justification": a.get("justification_text", ""),
                    "confidence": a.get("confidence", ""),
                }
                for a in assessments
            ]

        # Use sys.stdout for clean JSON (no Rich markup) when piped
        sys.stdout.write(json.dumps(output, indent=2) + "\n")
