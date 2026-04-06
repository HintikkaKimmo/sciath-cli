"""
Static Yocto layer resolver — parse BSP layers without a build environment.

Walks a Yocto layer's directory tree and extracts:
- Recipe files (.bb) and their overrides (.bbappend)
- Patches referenced via SRC_URI file:// entries
- FILESEXTRAPATHS for non-standard patch locations
- BBFILE_PRIORITY from layer.conf for override ordering
- Kernel config fragments (.cfg files)

Limitations (v1):
- Single-layer parsing only (no cross-layer resolution)
- No BitBake variable expansion (${WORKDIR}, ${PV}, etc.)
- No machine overrides or conditional expressions
- Unsupported patterns logged as warnings, not errors

Reports parse_confidence (0.0-1.0) indicating what fraction of
recipes were fully resolved.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns for extracting info from recipe files
_SRC_URI_RE = re.compile(r'SRC_URI\s*[+=.]+\s*"([^"]*)"', re.MULTILINE)
_SRC_URI_APPEND_RE = re.compile(r'SRC_URI:append\s*=\s*"([^"]*)"', re.MULTILINE)
_FILESEXTRAPATHS_RE = re.compile(
    r'FILESEXTRAPATHS:prepend\s*:=\s*"([^"]*)"', re.MULTILINE
)
_BBFILE_PRIORITY_RE = re.compile(r"BBFILE_PRIORITY[^=]*=\s*\"?(\d+)\"?")
_CVE_TAG_RE = re.compile(r"CVE[-:](\d{4}[-:]\d{4,})", re.IGNORECASE)
_UPSTREAM_STATUS_RE = re.compile(r"Upstream-Status:\s*(\S+)", re.IGNORECASE)


@dataclass
class PatchInfo:
    """Information about a patch file found in a BSP layer."""

    file_path: Path
    recipe: str
    cve_ids: list[str] = field(default_factory=list)
    upstream_status: str = ""  # Backport, Submitted, Pending, Inappropriate, etc.
    classification: str = "unknown"  # backport, vendor-only, cve-tagged, unknown


@dataclass
class GitSourceInfo:
    """A git:// source reference found in a recipe's SRC_URI."""

    uri: str
    recipe: str
    branch: str = ""
    srcrev: str = ""


@dataclass
class RecipeInfo:
    """Information about a recipe (.bb or .bbappend) in a BSP layer."""

    file_path: Path
    name: str
    patches: list[PatchInfo] = field(default_factory=list)
    git_sources: list[GitSourceInfo] = field(default_factory=list)
    filesextrapaths: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class LayerInfo:
    """Resolved information about a Yocto BSP layer."""

    layer_path: Path
    layer_name: str = ""
    priority: int = 6  # Default Yocto layer priority
    recipes: list[RecipeInfo] = field(default_factory=list)
    kernel_config_fragments: list[Path] = field(default_factory=list)
    parse_confidence: float = 1.0  # 0.0-1.0
    warnings: list[str] = field(default_factory=list)

    @property
    def total_patches(self) -> int:
        return sum(len(r.patches) for r in self.recipes)

    @property
    def recipes_with_errors(self) -> int:
        return sum(1 for r in self.recipes if r.parse_errors)

    def summary(self) -> str:
        parts = [
            f"Layer: {self.layer_name} (priority {self.priority})",
            f"{len(self.recipes)} recipes, {self.total_patches} patches",
            f"confidence: {self.parse_confidence:.0%}",
        ]
        if self.kernel_config_fragments:
            parts.append(f"{len(self.kernel_config_fragments)} kconfig fragments")
        if self.warnings:
            parts.append(f"{len(self.warnings)} warnings")
        return ", ".join(parts)


def resolve_layer(layer_path: Path) -> LayerInfo:
    """Parse a Yocto layer directory and extract structured information.

    Args:
        layer_path: Path to the layer root (contains conf/layer.conf)

    Returns:
        LayerInfo with all discovered recipes, patches, and config fragments.
    """
    layer_path = layer_path.resolve()
    info = LayerInfo(layer_path=layer_path)

    # Parse layer.conf for name and priority
    layer_conf = layer_path / "conf" / "layer.conf"
    if layer_conf.exists():
        _parse_layer_conf(layer_conf, info)
    else:
        info.warnings.append("No conf/layer.conf found")

    # Find all recipe files
    recipe_files = list(layer_path.rglob("*.bb")) + list(layer_path.rglob("*.bbappend"))

    total_recipes = 0
    failed_recipes = 0

    for recipe_file in recipe_files:
        total_recipes += 1
        recipe = _parse_recipe(recipe_file, layer_path)
        if recipe.parse_errors:
            failed_recipes += 1
        info.recipes.append(recipe)

    # Find kernel config fragments
    info.kernel_config_fragments = list(layer_path.rglob("*.cfg"))

    # Calculate parse confidence
    if total_recipes > 0:
        info.parse_confidence = 1.0 - (failed_recipes / total_recipes)
    else:
        info.parse_confidence = 1.0

    logger.info("Resolved layer: %s", info.summary())
    return info


def _parse_layer_conf(layer_conf: Path, info: LayerInfo) -> None:
    """Extract layer name and priority from layer.conf."""
    try:
        text = layer_conf.read_text()
    except OSError as e:
        info.warnings.append(f"Cannot read layer.conf: {e}")
        return

    # Layer name: BBFILE_COLLECTIONS += "meta-toradex"
    name_match = re.search(r'BBFILE_COLLECTIONS\s*\+?=\s*"([^"]*)"', text)
    if name_match:
        info.layer_name = name_match.group(1).strip()

    # Priority
    prio_match = _BBFILE_PRIORITY_RE.search(text)
    if prio_match:
        try:
            info.priority = int(prio_match.group(1))
        except ValueError:
            pass


def _parse_recipe(recipe_file: Path, layer_path: Path) -> RecipeInfo:
    """Parse a single recipe file for patches and metadata."""
    name = recipe_file.stem.split("_")[0]  # e.g., linux-toradex_5.15.bb → linux-toradex
    recipe = RecipeInfo(file_path=recipe_file, name=name)

    try:
        text = recipe_file.read_text()
    except OSError as e:
        recipe.parse_errors.append(f"Cannot read: {e}")
        return recipe

    # Extract FILESEXTRAPATHS
    for match in _FILESEXTRAPATHS_RE.finditer(text):
        paths = match.group(1).split(":")
        recipe.filesextrapaths.extend(p.strip() for p in paths if p.strip())

    # Extract patches from SRC_URI
    patch_refs = _extract_patch_refs(text)

    # Resolve each patch reference to an actual file
    for patch_ref in patch_refs:
        patch_info = _resolve_patch(patch_ref, recipe_file, layer_path, recipe.filesextrapaths)
        if patch_info:
            recipe.patches.append(patch_info)
        else:
            recipe.parse_errors.append(f"Cannot resolve patch: {patch_ref}")

    # Extract git:// source references (forked kernels, u-boot, etc.)
    recipe.git_sources = _extract_git_sources(text, name)

    # Scan for orphan patches: .patch/.diff files next to the recipe
    # that aren't in SRC_URI (common in vendor layers)
    referenced_names = {Path(ref).name for ref in patch_refs}
    orphans = _find_orphan_patches(recipe_file, name, layer_path, referenced_names)
    recipe.patches.extend(orphans)

    return recipe


def _extract_patch_refs(text: str) -> list[str]:
    """Extract patch file references from SRC_URI in recipe text."""
    patches = []

    # Match SRC_URI = "..." and SRC_URI += "..." and SRC_URI:append = "..."
    for pattern in [_SRC_URI_RE, _SRC_URI_APPEND_RE]:
        for match in pattern.finditer(text):
            uri_block = match.group(1)
            # Split on whitespace and backslash-newlines
            entries = uri_block.replace("\\\n", " ").split()
            for entry in entries:
                entry = entry.strip()
                if entry.startswith("file://") and (
                    entry.endswith(".patch") or entry.endswith(".diff")
                ):
                    # Strip file:// prefix
                    patches.append(entry[7:])

    return patches


def _resolve_patch(
    patch_ref: str,
    recipe_file: Path,
    layer_path: Path,
    filesextrapaths: list[str],
) -> Optional[PatchInfo]:
    """Resolve a patch filename to an actual file on disk."""
    recipe_dir = recipe_file.parent
    recipe_name = recipe_file.stem.split("_")[0]

    # Search order for patch files:
    # 1. Recipe-name subdirectory next to the recipe file
    # 2. "files" subdirectory next to the recipe file
    # 3. FILESEXTRAPATHS directories (can't fully resolve without variable expansion)
    # 4. Direct path from layer root

    search_dirs = [
        recipe_dir / recipe_name,
        recipe_dir / "files",
        recipe_dir,
    ]

    # Add FILESEXTRAPATHS that don't contain variables
    for extra in filesextrapaths:
        if "$" not in extra and "{" not in extra:
            p = Path(extra)
            if p.is_absolute() and p.exists():
                search_dirs.append(p)
            else:
                # Try relative to layer
                rel = layer_path / extra
                if rel.exists():
                    search_dirs.append(rel)

    for search_dir in search_dirs:
        candidate = search_dir / patch_ref
        if candidate.exists():
            return _analyze_patch(candidate, recipe_name)

    return None


def _analyze_patch(patch_path: Path, recipe: str) -> PatchInfo:
    """Analyze a patch file for CVE tags and upstream status."""
    info = PatchInfo(file_path=patch_path, recipe=recipe)

    try:
        # Read first 2KB for header analysis (enough for metadata)
        text = patch_path.read_text(errors="replace")[:2048]
    except OSError:
        return info

    # Extract CVE IDs from filename and content
    filename_cves = _CVE_TAG_RE.findall(patch_path.name)
    content_cves = _CVE_TAG_RE.findall(text)
    all_cves = set()
    for cve in filename_cves + content_cves:
        cve_id = f"CVE-{cve.replace(':', '-')}"
        all_cves.add(cve_id)
    info.cve_ids = sorted(all_cves)

    # Extract Upstream-Status
    status_match = _UPSTREAM_STATUS_RE.search(text)
    if status_match:
        info.upstream_status = status_match.group(1)

    # Classify the patch
    if info.cve_ids:
        info.classification = "cve-tagged"
    elif info.upstream_status.lower() in ("backport", "accepted"):
        info.classification = "backport"
    elif info.upstream_status.lower() in ("inappropriate", "denied"):
        info.classification = "vendor-only"
    else:
        info.classification = "unknown"

    return info


def _extract_git_sources(text: str, recipe_name: str) -> list[GitSourceInfo]:
    """Extract git:// and https:// source URIs from SRC_URI."""
    sources = []
    git_uri_re = re.compile(r'((?:git|https?)://[^\s;"]+)')
    branch_re = re.compile(r'branch=([^\s;]+)')
    srcrev_re = re.compile(r'SRCREV\s*=\s*"([^"]+)"')

    srcrev = ""
    srcrev_match = srcrev_re.search(text)
    if srcrev_match:
        srcrev = srcrev_match.group(1)

    for pattern in [_SRC_URI_RE, _SRC_URI_APPEND_RE]:
        for match in pattern.finditer(text):
            uri_block = match.group(1).replace("\\\n", " ")
            for entry in uri_block.split():
                entry = entry.strip()
                git_match = git_uri_re.match(entry)
                if git_match and ".git" in entry:
                    uri = git_match.group(1)
                    branch = ""
                    branch_match = branch_re.search(entry)
                    if branch_match:
                        branch = branch_match.group(1)
                    sources.append(GitSourceInfo(
                        uri=uri,
                        recipe=recipe_name,
                        branch=branch,
                        srcrev=srcrev,
                    ))

    return sources


def _find_orphan_patches(
    recipe_file: Path,
    recipe_name: str,
    layer_path: Path,
    referenced_names: set[str],
) -> list[PatchInfo]:
    """Find .patch/.diff files near a recipe that aren't in SRC_URI.

    Vendor layers often have patches in files/ or recipe-name/ directories
    that are applied via bbappend or FILESPATH without explicit file:// URIs.
    """
    orphans: list[PatchInfo] = []
    recipe_dir = recipe_file.parent

    search_dirs = [
        recipe_dir / recipe_name,
        recipe_dir / "files",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for patch_file in search_dir.iterdir():
            if patch_file.suffix in (".patch", ".diff") and patch_file.name not in referenced_names:
                patch_info = _analyze_patch(patch_file, recipe_name)
                orphans.append(patch_info)

    return orphans
