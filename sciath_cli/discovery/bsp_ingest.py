"""
BSP ingestion — analyze a vendor BSP layer and produce a flat JSON profile.

Orchestrates: clone/read layer → resolve recipes/patches → merge kconfig
fragments → classify patches → store as JSON.

The output JSON is consumed by the scan pipeline to suppress CVEs that
are already patched by the BSP vendor.
"""

import json
import logging
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sciath_cli.discovery.layer_resolver import PatchInfo, resolve_layer

logger = logging.getLogger(__name__)


@dataclass
class BspProfile:
    """Complete security profile for a BSP family."""

    vendor: str
    som: str
    bsp_repo: str
    analyzed_commit: str = ""
    analyzed_date: str = ""
    patches: list[dict[str, Any]] = field(default_factory=list)
    suppressions: list[dict[str, str]] = field(default_factory=list)
    kernel_config: dict[str, str] = field(default_factory=dict)
    ambiguous_configs: list[str] = field(default_factory=list)
    parse_confidence: float = 1.0
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "BspProfile":
        data = json.loads(text)
        return cls(**data)


def ingest_bsp(
    layer_path: Path,
    vendor: str,
    som: str,
    bsp_repo: str = "",
) -> BspProfile:
    """Analyze a BSP layer and produce a security profile.

    Args:
        layer_path: Path to the BSP layer directory (must exist).
        vendor: BSP vendor name (e.g., "toradex").
        som: System-on-Module name (e.g., "verdin-imx8mp").
        bsp_repo: Git repository URL for the BSP.

    Returns:
        BspProfile with patches, suppressions, and kernel config.
    """
    layer_path = layer_path.resolve()
    profile = BspProfile(
        vendor=vendor,
        som=som,
        bsp_repo=bsp_repo,
        analyzed_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    )

    # Get current commit hash if it's a git repo
    profile.analyzed_commit = _get_git_commit(layer_path)

    # Resolve the layer
    layer_info = resolve_layer(layer_path)
    profile.parse_confidence = layer_info.parse_confidence
    profile.warnings = layer_info.warnings

    # Collect all patches with metadata
    for recipe in layer_info.recipes:
        for patch in recipe.patches:
            profile.patches.append(_patch_to_dict(patch))

            # Generate suppressions from CVE-tagged patches
            for cve_id in patch.cve_ids:
                profile.suppressions.append({
                    "cve_id": cve_id,
                    "reason": "patch",
                    "confidence": "high" if patch.upstream_status.lower() in ("backport", "accepted") else "medium",
                    "evidence": f"Patch {patch.file_path.name} in recipe {patch.recipe}, "
                                f"upstream status: {patch.upstream_status or 'unknown'}",
                })

    # Merge kernel config fragments
    _merge_kconfig_fragments(layer_info.kernel_config_fragments, profile)

    logger.info(
        "BSP ingestion complete: %s %s — %d patches, %d suppressions, confidence %.0f%%",
        vendor, som, len(profile.patches), len(profile.suppressions),
        profile.parse_confidence * 100,
    )
    return profile


def save_profile(profile: BspProfile, output_dir: Path) -> Path:
    """Save a BSP profile to a JSON file.

    Returns the path to the written file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{profile.vendor}_{profile.som}.json".replace("-", "_")
    output_path = output_dir / filename
    output_path.write_text(profile.to_json() + "\n")
    logger.info("Saved BSP profile to %s", output_path)
    return output_path


def load_profile(profile_path: Path) -> Optional[BspProfile]:
    """Load a BSP profile from a JSON file."""
    try:
        text = profile_path.read_text()
        return BspProfile.from_json(text)
    except (json.JSONDecodeError, OSError, TypeError) as e:
        logger.warning("Cannot load BSP profile %s: %s", profile_path, e)
        return None


def check_staleness(profile: BspProfile, layer_path: Path) -> Optional[str]:
    """Check if a BSP profile is stale (analyzed commit != current HEAD).

    Returns a warning message if stale, or None if current.
    """
    current_commit = _get_git_commit(layer_path)
    if not current_commit or not profile.analyzed_commit:
        return None  # Can't check, don't warn
    if current_commit != profile.analyzed_commit:
        return (
            f"BSP profile was analyzed at commit {profile.analyzed_commit[:8]} "
            f"but layer is now at {current_commit[:8]}. "
            f"Results may be outdated. Re-run ingestion to update."
        )
    return None


def _get_git_commit(path: Path) -> str:
    """Get the current git commit hash for a directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(path),
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def _patch_to_dict(patch: PatchInfo) -> dict[str, Any]:
    """Convert a PatchInfo to a serializable dict."""
    return {
        "recipe": patch.recipe,
        "file": patch.file_path.name,
        "cve_ids": patch.cve_ids,
        "upstream_status": patch.upstream_status,
        "classification": patch.classification,
    }


def _merge_kconfig_fragments(fragments: list[Path], profile: BspProfile) -> None:
    """Merge kernel config fragments into a single config dict.

    Later fragments override earlier ones (simulating Yocto's merge order).
    Options not explicitly set are added to ambiguous_configs since we
    can't replicate `make olddefconfig` without a build environment.
    """
    for fragment in sorted(fragments):  # Sort for deterministic ordering
        try:
            text = fragment.read_text()
        except OSError:
            profile.warnings.append(f"Cannot read kconfig fragment: {fragment.name}")
            continue

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                # Check for "# CONFIG_FOO is not set" pattern
                if line.startswith("# CONFIG_") and line.endswith(" is not set"):
                    key = line.split()[1]
                    profile.kernel_config[key] = "n"
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                profile.kernel_config[key.strip()] = value.strip()
