"""
Sciath build system artifact discovery.

Shared module for discovering firmware artifacts across build systems.
Each build system implements BuildSystemDiscovery ABC.
"""

__version__ = "0.1.0"

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery

__all__ = ["ArtifactBundle", "BuildSystemDiscovery", "auto_discover"]


def auto_discover(build_dir: str, build_system: str = "") -> ArtifactBundle:
    """
    Auto-detect build system and collect artifacts.

    If build_system is specified, uses that discovery module directly.
    Otherwise, tries each registered discovery module until one detects
    a matching build tree.
    """
    from pathlib import Path

    path = Path(build_dir).resolve()
    if not path.is_absolute():
        raise ValueError(f"build_dir must be an absolute path, got: {build_dir}")
    if not path.is_dir():
        raise FileNotFoundError(f"Build directory not found: {build_dir}")

    # Registry of discovery modules (imported lazily)
    _registry: dict[str, type[BuildSystemDiscovery]] = {}

    if build_system:
        # Direct dispatch
        mod = _load_module(build_system)
        if mod is None:
            raise ValueError(f"Unknown build system: {build_system}")
        return mod().collect(path)

    # Auto-detect: try each module
    for name in ["yocto", "buildroot", "debian", "openwrt"]:
        mod = _load_module(name)
        if mod and mod().detect(path):
            return mod().collect(path)

    raise RuntimeError(
        f"Could not detect build system in {build_dir}. "
        "Pass --build-system explicitly."
    )


def _load_module(name: str) -> type[BuildSystemDiscovery] | None:
    """Lazily load a discovery module by name."""
    try:
        if name == "yocto":
            from sciath_cli.discovery.yocto import YoctoDiscovery
            return YoctoDiscovery
        if name == "buildroot":
            from sciath_cli.discovery.buildroot import BuildrootDiscovery
            return BuildrootDiscovery
        if name == "debian":
            from sciath_cli.discovery.debian import DebianDiscovery
            return DebianDiscovery
        if name == "openwrt":
            from sciath_cli.discovery.openwrt import OpenwrtDiscovery
            return OpenwrtDiscovery
    except ImportError:
        pass
    return None
