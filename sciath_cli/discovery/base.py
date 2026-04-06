"""
Base classes for build system artifact discovery.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ArtifactBundle:
    """
    Collection of firmware artifacts discovered from a build tree.

    All paths are absolute and verified to exist at discovery time.
    """

    sbom: Optional[Path] = None
    sbom_format: str = ""  # "spdx", "cyclonedx", "yocto-manifest"
    kconfig: Optional[Path] = None
    dtb: list[Path] = field(default_factory=list)
    busybox_config: Optional[Path] = None
    packageconfigs: dict[str, list[str]] = field(default_factory=dict)
    packageconfig_suppressions: dict[str, list[str]] = field(default_factory=dict)
    yocto_machine: str = ""
    yocto_distro: str = ""
    kernel_version: str = ""
    build_system: str = ""
    schema_version: str = "1.1"
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def has_sbom(self) -> bool:
        return self.sbom is not None and self.sbom.exists()

    @property
    def has_kconfig(self) -> bool:
        return self.kconfig is not None and self.kconfig.exists()

    @property
    def artifact_count(self) -> int:
        """Number of non-empty artifact types discovered."""
        count = 0
        if self.has_sbom:
            count += 1
        if self.has_kconfig:
            count += 1
        if self.dtb:
            count += 1
        if self.busybox_config:
            count += 1
        if self.packageconfigs:
            count += 1
        return count

    def summary(self) -> str:
        """Human-readable summary of discovered artifacts."""
        parts = []
        if self.has_sbom:
            parts.append(f"SBOM ({self.sbom_format})")
        if self.has_kconfig:
            parts.append("kconfig")
        if self.dtb:
            parts.append(f"{len(self.dtb)} DTB(s)")
        if self.busybox_config:
            parts.append("busybox config")
        if self.packageconfigs:
            parts.append(f"PACKAGECONFIG ({len(self.packageconfigs)} recipes)")
        if self.packageconfig_suppressions:
            total = sum(len(v) for v in self.packageconfig_suppressions.values())
            parts.append(f"{total} CVEs suppressed by PACKAGECONFIG")
        if not parts:
            return "No artifacts found"
        return f"Found: {', '.join(parts)} [{self.build_system}]"


class BuildSystemDiscovery(ABC):
    """
    Abstract base for build system artifact discovery.

    Implementations must:
    - detect() → check if the build directory matches this build system
    - collect() → walk the build tree and return an ArtifactBundle

    Path safety: collect() must validate that all discovered paths are
    within the build_dir. No directory traversal outside the build tree.
    """

    @abstractmethod
    def detect(self, build_dir: Path) -> bool:
        """Return True if this build system is detected in build_dir."""

    @abstractmethod
    def collect(self, build_dir: Path) -> ArtifactBundle:
        """Collect all scannable artifacts from the build tree."""

    def _validate_path(self, path: Path, build_dir: Path) -> bool:
        """Ensure path is within build_dir (no traversal attacks)."""
        try:
            path.resolve().relative_to(build_dir.resolve())
            return True
        except ValueError:
            return False
