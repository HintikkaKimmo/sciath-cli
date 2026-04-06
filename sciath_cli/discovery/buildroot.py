"""
Buildroot build system artifact discovery.

TODO: Implement when first Buildroot customer requests it.
"""

from pathlib import Path

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery


class BuildrootDiscovery(BuildSystemDiscovery):
    def detect(self, build_dir: Path) -> bool:
        """Buildroot builds have a .config and output/build/ directory."""
        return (
            (build_dir / ".config").exists()
            and (build_dir / "output" / "build").exists()
        )

    def collect(self, build_dir: Path) -> ArtifactBundle:
        raise NotImplementedError("Buildroot discovery not yet implemented")
