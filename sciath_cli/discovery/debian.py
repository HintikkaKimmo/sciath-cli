"""
Debian/Ubuntu build system artifact discovery.

TODO: Implement when first Debian customer requests it.
"""

from pathlib import Path

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery


class DebianDiscovery(BuildSystemDiscovery):
    def detect(self, build_dir: Path) -> bool:
        """Debian builds have debian/ directory with control file."""
        return (build_dir / "debian" / "control").exists()

    def collect(self, build_dir: Path) -> ArtifactBundle:
        raise NotImplementedError("Debian discovery not yet implemented")
