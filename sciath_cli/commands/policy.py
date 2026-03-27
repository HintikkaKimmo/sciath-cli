"""
Policy commands: list, show, create, update, delete, history, import-vex, merge.
"""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from sciath_cli.api import SciathAPI, SciathAPIError
from sciath_cli.config import requires_auth
from sciath_cli.console import console

app = typer.Typer(help="Manage filter policies.")


@app.command("list")
@requires_auth
def list_policies(
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Filter by name"),
    config=None,
):
    """List filter policies for the current customer."""
    with SciathAPI(config) as api:
        try:
            result = api.list_policies(search=search)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    if not items:
        console.print("[dim]No policies found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Rules", justify="right")
    table.add_column("Version", justify="right")
    table.add_column("Updated")
    table.add_column("ID", style="dim")

    for p in items:
        table.add_row(
            p["name"],
            str(p.get("rule_count", "—")),
            f"v{p.get('version', '?')}",
            p.get("updated_at", "")[:10],
            str(p["id"])[:8],
        )

    console.print(table)


@app.command()
@requires_auth
def show(
    name: str = typer.Argument(..., help="Policy name or ID"),
    config=None,
):
    """Show a policy's details and rules."""
    policy = _find_policy(config, name)
    if not policy:
        raise typer.Exit(1)

    console.print(f"\n[bold]{policy['name']}[/bold] v{policy['version']}")
    if policy.get("description"):
        console.print(f"[dim]{policy['description']}[/dim]")
    console.print(f"Rules: {policy.get('rule_count', 0)}  |  Hash: {policy.get('content_hash', '')[:12]}...")
    console.print(f"Created: {policy.get('created_at', '')[:10]}  |  Updated: {policy.get('updated_at', '')[:10]}")

    # Show rules
    content = policy.get("content_raw", {})
    rules = content.get("rules", []) if isinstance(content, dict) else []
    if rules:
        console.print(f"\n[bold]Rules ({len(rules)}):[/bold]")
        for r in rules:
            match = r.get("match", {})
            result = r.get("result", {})
            console.print(
                f"  {r.get('id', '?'):15s}  "
                f"{match.get('type', '?'):20s}  "
                f"{str(match.get('value', ''))[:30]:30s}  "
                f"→ {result.get('status', '?')} ({result.get('confidence', '?')})"
            )


@app.command()
@requires_auth
def create(
    name: str = typer.Argument(..., help="Policy name"),
    file: Path = typer.Option(..., "--file", "-f", help="Path to custom_filter.json"),
    description: str = typer.Option("", "--description", "-d", help="Policy description"),
    config=None,
):
    """Create a new filter policy from a JSON file."""
    if not file.exists():
        console.print(f"[red]✗ File not found: {file}[/red]")
        raise typer.Exit(1)

    try:
        content = json.loads(file.read_text())
    except json.JSONDecodeError as exc:
        console.print(f"[red]✗ Invalid JSON: {exc}[/red]")
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        try:
            result = api.create_policy(name=name, content=content, description=description)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    rule_count = result.get("rule_count", 0)
    console.print(
        f"[green]✓[/green] Created policy [bold]{result['name']}[/bold] "
        f"v{result['version']} ({rule_count} rules)"
    )


@app.command()
@requires_auth
def update(
    name: str = typer.Argument(..., help="Policy name"),
    file: Path = typer.Option(..., "--file", "-f", help="Path to updated custom_filter.json"),
    config=None,
):
    """Update a policy's content. Bumps version and logs history."""
    policy = _find_policy(config, name)
    if not policy:
        raise typer.Exit(1)

    if not file.exists():
        console.print(f"[red]✗ File not found: {file}[/red]")
        raise typer.Exit(1)

    try:
        content = json.loads(file.read_text())
    except json.JSONDecodeError as exc:
        console.print(f"[red]✗ Invalid JSON: {exc}[/red]")
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        try:
            result = api.update_policy(policy["id"], {"content_raw": content})
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    console.print(
        f"[green]✓[/green] Updated [bold]{result['name']}[/bold] → "
        f"v{result['version']} ({result.get('rule_count', 0)} rules)"
    )


@app.command()
@requires_auth
def delete(
    name: str = typer.Argument(..., help="Policy name"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    config=None,
):
    """Delete a filter policy."""
    policy = _find_policy(config, name)
    if not policy:
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Delete policy '{policy['name']}' v{policy['version']}?")
        if not confirm:
            raise typer.Exit(0)

    with SciathAPI(config) as api:
        try:
            api.delete_policy(policy["id"])
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    console.print(f"[green]✓[/green] Deleted policy [bold]{policy['name']}[/bold]")


@app.command()
@requires_auth
def history(
    name: str = typer.Argument(..., help="Policy name"),
    config=None,
):
    """Show version history for a policy."""
    policy = _find_policy(config, name)
    if not policy:
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        try:
            result = api.policy_history(policy["id"])
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    items = result.get("items", [])
    console.print(f"\n[bold]{policy['name']}[/bold] — version history")

    if not items:
        console.print("[dim]No history (only the current version exists).[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Version", justify="right")
    table.add_column("Hash", style="dim")
    table.add_column("Edited By")
    table.add_column("Timestamp")

    for h in items:
        table.add_row(
            f"v{h['version']}",
            h.get("content_hash", "")[:12],
            h.get("edited_by_id", "—")[:8] if h.get("edited_by_id") else "—",
            h.get("timestamp", "")[:19],
        )

    console.print(table)


@app.command("import-vex")
@requires_auth
def import_vex(
    name: str = typer.Argument(..., help="Policy name to create"),
    file: Path = typer.Option(..., "--file", "-f", help="Path to CycloneDX VEX document"),
    description: str = typer.Option("", "--description", "-d", help="Policy description"),
    trust_vendor: bool = typer.Option(False, "--trust-vendor", help="Elevate confidence to HIGH (requires admin)"),
    config=None,
):
    """Import a CycloneDX VEX document as a filter policy."""
    if not file.exists():
        console.print(f"[red]✗ File not found: {file}[/red]")
        raise typer.Exit(1)

    try:
        vex_content = json.loads(file.read_text())
    except json.JSONDecodeError as exc:
        console.print(f"[red]✗ Invalid JSON: {exc}[/red]")
        raise typer.Exit(1)

    with SciathAPI(config) as api:
        try:
            result = api.import_vex_policy(
                name=name,
                vex_content=vex_content,
                description=description,
                trust_vendor=trust_vendor,
            )
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            raise typer.Exit(1)

    confidence = "HIGH" if trust_vendor else "MEDIUM"
    console.print(
        f"[green]✓[/green] Imported VEX as policy [bold]{result['name']}[/bold] "
        f"v{result['version']} ({result.get('rule_count', 0)} rules, confidence={confidence})"
    )


@app.command()
@requires_auth
def merge(
    names: list[str] = typer.Argument(..., help="Policy names to merge"),
    output: Path = typer.Option("merged_policy.json", "--output", "-o", help="Output file"),
    config=None,
):
    """Merge multiple policies into a single JSON file (client-side composition)."""
    if len(names) < 2:
        console.print("[red]✗ Need at least 2 policy names to merge.[/red]")
        raise typer.Exit(1)

    all_rules = []
    seen_ids: set = set()

    with SciathAPI(config) as api:
        for name in names:
            try:
                result = api.list_policies(search=name)
            except SciathAPIError as exc:
                console.print(f"[red]✗ {exc}[/red]")
                raise typer.Exit(1)

            items = result.get("items", [])
            match = next(
                (p for p in items if p["name"].lower() == name.lower()),
                None,
            )
            if not match:
                console.print(f"[red]✗ Policy not found: {name}[/red]")
                raise typer.Exit(1)

            # Fetch full policy to get content_raw
            try:
                policy = api.get_policy(match["id"])
            except SciathAPIError as exc:
                console.print(f"[red]✗ {exc}[/red]")
                raise typer.Exit(1)

            content = policy.get("content_raw", {})
            rules = content.get("rules", []) if isinstance(content, dict) else []
            for rule in rules:
                rule_id = rule.get("id", "")
                if rule_id in seen_ids:
                    console.print(f"[yellow]⚠ Duplicate rule ID '{rule_id}' — last one wins[/yellow]")
                    all_rules = [r for r in all_rules if r.get("id") != rule_id]
                seen_ids.add(rule_id)
                all_rules.append(rule)

            console.print(f"  [dim]+ {policy['name']} v{policy['version']} ({len(rules)} rules)[/dim]")

    merged = {
        "version": "1",
        "description": f"Merged from: {', '.join(names)}",
        "rules": all_rules,
    }

    output.write_text(json.dumps(merged, indent=2))
    console.print(
        f"\n[green]✓[/green] Merged {len(names)} policies → "
        f"[bold]{output}[/bold] ({len(all_rules)} rules)"
    )


# ── Helpers ────────────────────────────────────────────────────────────────


def _find_policy(config, name_or_id: str) -> Optional[dict]:
    """Look up a policy by name (case-insensitive) or ID prefix."""
    with SciathAPI(config) as api:
        try:
            result = api.list_policies(search=name_or_id)
        except SciathAPIError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            return None

    items = result.get("items", [])
    match = next(
        (p for p in items
         if p["name"].lower() == name_or_id.lower()
         or str(p["id"]).startswith(name_or_id)),
        None,
    )
    if not match:
        console.print(f"[red]✗ Policy not found: {name_or_id}[/red]")
        return None

    return match
