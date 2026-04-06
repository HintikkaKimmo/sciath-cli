"""
OpenWrt build system artifact discovery.

TODO: Implement when first OpenWrt customer requests it.
"""

from pathlib import Path

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery


class OpenwrtDiscovery(BuildSystemDiscovery):
    def detect(self, build_dir: Path) -> bool:
        """OpenWrt builds have feeds.conf and include/toplevel.mk."""
        return (
            (build_dir / "feeds.conf").exists()
            or (build_dir / "feeds.conf.default").exists()
        ) and (build_dir / "include" / "toplevel.mk").exists()

    def collect(self, build_dir: Path) -> ArtifactBundle:
        raise NotImplementedError("OpenWrt discovery not yet implemented")
