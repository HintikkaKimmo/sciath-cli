"""
sciath init — Set up Sciath in a Yocto build environment.

Detects the build system, extracts the bundled meta-sciath layer,
registers it with bitbake-layers, and configures local.conf.

Hard requirement: never break the Yocto build. All modifications are
backed up and validated before writing.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="Set up Sciath in a build environment.")

# Location of the bundled meta layer inside the installed package
_META_LAYER_SRC = Path(__file__).parent.parent / "meta_layer"


def _detect_build_dir(explicit: Optional[Path]) -> Path:
    """Find the Yocto build directory.

    Search order:
    1. Explicit --build-dir argument
    2. BUILDDIR environment variable (set by oe-init-build-env)
    3. Current working directory (if it has conf/local.conf)
    4. Walk up from CWD looking for conf/local.conf
    """
    if explicit:
        bd = explicit.resolve()
        if (bd / "conf" / "local.conf").exists():
            return bd
        console.print(f"[red]Error:[/red] {bd} does not contain conf/local.conf")
        raise typer.Exit(1)

    # BUILDDIR env var (set by oe-init-build-env)
    env_builddir = os.environ.get("BUILDDIR")
    if env_builddir:
        bd = Path(env_builddir).resolve()
        if (bd / "conf" / "local.conf").exists():
            return bd

    # CWD
    cwd = Path.cwd().resolve()
    if (cwd / "conf" / "local.conf").exists():
        return cwd

    # Walk up from CWD
    for parent in cwd.parents:
        if (parent / "conf" / "local.conf").exists():
            return parent

    console.print(
        "[red]Error:[/red] Could not find a Yocto build directory.\n"
        "Run this command from your build directory, or use --build-dir.\n"
        "Make sure you've sourced oe-init-build-env first."
    )
    raise typer.Exit(1)


def _backup_file(path: Path) -> Path:
    """Create a backup of a file before modifying it."""
    backup = path.with_suffix(path.suffix + ".sciath-backup")
    shutil.copy2(path, backup)
    return backup


def _layer_already_added(build_dir: Path, layer_name: str) -> bool:
    """Check if the layer is already in bblayers.conf."""
    bblayers = build_dir / "conf" / "bblayers.conf"
    if not bblayers.exists():
        return False
    text = bblayers.read_text()
    return layer_name in text


def _sciath_already_configured(build_dir: Path) -> bool:
    """Check if SCIATH_ variables are already in local.conf."""
    local_conf = build_dir / "conf" / "local.conf"
    text = local_conf.read_text()
    return "SCIATH_API_KEY" in text


def _extract_layer(build_dir: Path, layer_dir: Optional[Path]) -> Path:
    """Extract the bundled meta-sciath layer to the filesystem."""
    if layer_dir:
        dest = layer_dir.resolve()
    else:
        # Default: sibling of build dir in a sources/ directory
        dest = build_dir.parent / "sources" / "meta-sciath"

    if dest.exists():
        console.print(f"[yellow]Layer already exists at {dest}[/yellow]")
        return dest

    if not _META_LAYER_SRC.exists():
        console.print(
            "[red]Error:[/red] Bundled meta-sciath layer not found.\n"
            "This may indicate a broken installation. Try: pip install --force-reinstall sciath"
        )
        raise typer.Exit(1)

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(_META_LAYER_SRC, dest)
    console.print(f"[green]Extracted meta-sciath layer to {dest}[/green]")
    return dest


def _add_layer(build_dir: Path, layer_path: Path) -> bool:
    """Register the layer with bitbake-layers."""
    try:
        result = subprocess.run(
            ["bitbake-layers", "add-layer", str(layer_path)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(build_dir),
        )
        if result.returncode == 0:
            console.print("[green]Layer registered with bitbake-layers[/green]")
            return True
        else:
            # bitbake-layers not available — fall back to manual bblayers.conf edit
            logger.warning("bitbake-layers failed: %s", result.stderr)
            return _add_layer_manual(build_dir, layer_path)
    except FileNotFoundError:
        # bitbake-layers not on PATH
        return _add_layer_manual(build_dir, layer_path)
    except subprocess.TimeoutExpired:
        console.print("[yellow]Warning:[/yellow] bitbake-layers timed out. Adding layer manually.")
        return _add_layer_manual(build_dir, layer_path)


def _add_layer_manual(build_dir: Path, layer_path: Path) -> bool:
    """Manually add the layer to bblayers.conf."""
    bblayers = build_dir / "conf" / "bblayers.conf"
    if not bblayers.exists():
        console.print("[red]Error:[/red] conf/bblayers.conf not found")
        return False

    _backup_file(bblayers)
    text = bblayers.read_text()

    # Find the BBLAYERS assignment and append our layer
    if "BBLAYERS" in text:
        # Find last line before closing "
        lines = text.split("\n")
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip().endswith('"') and "BBLAYERS" not in lines[i]:
                # Insert before the closing quote line
                lines.insert(i, f"  {layer_path} \\")
                break
        text = "\n".join(lines)
        bblayers.write_text(text)
        console.print(f"[green]Added {layer_path} to bblayers.conf[/green]")
        return True
    else:
        console.print("[red]Error:[/red] Could not find BBLAYERS in bblayers.conf")
        return False


def _configure_local_conf(
    build_dir: Path,
    api_key: str,
    project_name: str,
) -> None:
    """Append Sciath configuration to local.conf."""
    local_conf = build_dir / "conf" / "local.conf"
    _backup_file(local_conf)

    config_block = f"""
# ── Sciath CRA compliance automation ──────────────────────────────────
# Docs: https://sciath.io/docs/yocto
SCIATH_API_KEY = "{api_key}"
SCIATH_PROJECT = "{project_name}"
SCIATH_ENABLED = "0"
# Set SCIATH_ENABLED = "1" to activate scanning during builds.
# Set SCIATH_FAIL_ON_ERROR = "1" to fail builds on Sciath errors (not recommended).
"""
    with open(local_conf, "a") as f:
        f.write(config_block)

    console.print("[green]Sciath configuration added to local.conf[/green]")
    console.print("[yellow]Note:[/yellow] SCIATH_ENABLED is set to \"0\" (disabled by default).")
    console.print("Set SCIATH_ENABLED = \"1\" in local.conf when ready to activate.")


@app.command("yocto")
def init_yocto(
    build_dir: Optional[Path] = typer.Option(
        None, "--build-dir", "-b",
        help="Yocto build directory [default: auto-detect from BUILDDIR or CWD]",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k",
        help="Sciath API key [default: prompt interactively]",
    ),
    project_name: Optional[str] = typer.Option(
        None, "--project", "-p",
        help="Sciath project name [default: prompt interactively]",
    ),
    layer_dir: Optional[Path] = typer.Option(
        None, "--layer-dir",
        help="Where to extract meta-sciath [default: ../sources/meta-sciath]",
    ),
    no_configure: bool = typer.Option(
        False, "--no-configure",
        help="Skip local.conf modification",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show what would be done without making changes",
    ),
    rollback: bool = typer.Option(
        False, "--rollback",
        help="Restore local.conf and bblayers.conf from backup",
    ),
) -> None:
    """Set up Sciath in a Yocto build environment."""
    bd = _detect_build_dir(build_dir)
    console.print(f"Build directory: [bold]{bd}[/bold]")

    # Rollback mode
    if rollback:
        _do_rollback(bd)
        return

    # Dry run mode
    if dry_run:
        _do_dry_run(bd, layer_dir)
        return

    # Check if already set up
    if _layer_already_added(bd, "meta-sciath") and _sciath_already_configured(bd):
        console.print("[green]Sciath is already configured in this build.[/green]")
        console.print("To reconfigure, edit conf/local.conf or run sciath init yocto --rollback first.")
        return

    # Extract layer
    layer_path = _extract_layer(bd, layer_dir)

    # Add layer to bblayers.conf
    if not _layer_already_added(bd, "meta-sciath"):
        if not _add_layer(bd, layer_path):
            console.print("[red]Failed to register layer. Add it manually:[/red]")
            console.print(f"  bitbake-layers add-layer {layer_path}")
    else:
        console.print("[yellow]Layer already in bblayers.conf[/yellow]")

    # Configure local.conf
    if not no_configure:
        if _sciath_already_configured(bd):
            console.print("[yellow]SCIATH_ variables already in local.conf[/yellow]")
        else:
            # Prompt for API key and project if not provided
            if not api_key:
                api_key = typer.prompt("Sciath API key", default="", show_default=False)
            if not project_name:
                project_name = typer.prompt("Sciath project name", default="my-project")
            _configure_local_conf(bd, api_key or "", project_name or "my-project")

    # Final instructions
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("1. Add [cyan]inherit sciath[/cyan] to your image recipe")
    console.print("2. Set [cyan]SCIATH_ENABLED = \"1\"[/cyan] in conf/local.conf")
    console.print("3. Run [cyan]bitbake your-image[/cyan]")
    console.print("4. Run [cyan]sciath scan status[/cyan] to see results")


def _do_dry_run(build_dir: Path, layer_dir: Optional[Path]) -> None:
    """Show what init would do without making changes."""
    console.print("[bold]Dry run — no changes will be made:[/bold]")
    console.print()

    if layer_dir:
        dest = layer_dir.resolve()
    else:
        dest = build_dir.parent / "sources" / "meta-sciath"

    if dest.exists():
        console.print(f"  Layer: already exists at {dest}")
    else:
        console.print(f"  Layer: would extract to {dest}")

    if _layer_already_added(build_dir, "meta-sciath"):
        console.print("  bblayers.conf: already has meta-sciath")
    else:
        console.print("  bblayers.conf: would add meta-sciath layer")

    if _sciath_already_configured(build_dir):
        console.print("  local.conf: already has SCIATH_ config")
    else:
        console.print("  local.conf: would append SCIATH_ configuration")


def _do_rollback(build_dir: Path) -> None:
    """Restore local.conf and bblayers.conf from sciath-backup files."""
    restored = 0
    for name in ["local.conf", "bblayers.conf"]:
        original = build_dir / "conf" / name
        backup = original.with_suffix(original.suffix + ".sciath-backup")
        if backup.exists():
            shutil.copy2(backup, original)
            console.print(f"[green]Restored {name} from backup[/green]")
            restored += 1
        else:
            console.print(f"[yellow]No backup found for {name}[/yellow]")

    if restored:
        console.print("[green]Rollback complete.[/green]")
    else:
        console.print("[yellow]Nothing to rollback — no backup files found.[/yellow]")
