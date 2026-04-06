"""
Yocto/OpenEmbedded build system artifact discovery.

Walks a Yocto build tree (BUILDDIR) and collects:
- SBOM from create-spdx or cve-check output
- Kernel .config from staging kernel dir
- DTBs from deploy dir
- Busybox .config from busybox workdir
- PACKAGECONFIG per recipe (from bitbake environment)
"""

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery
from sciath_cli.discovery.packageconfig_maps import lookup_suppressions

logger = logging.getLogger(__name__)

_RECIPE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]*$")


class YoctoDiscovery(BuildSystemDiscovery):
    """Discover artifacts from a Yocto/OE build tree."""

    def detect(self, build_dir: Path) -> bool:
        """Yocto builds have conf/local.conf and tmp/ directory."""
        return (
            (build_dir / "conf" / "local.conf").exists()
            and (build_dir / "tmp").exists()
        )

    def collect(self, build_dir: Path) -> ArtifactBundle:
        """Walk the Yocto build tree and collect all artifacts."""
        build_dir = build_dir.resolve()
        bundle = ArtifactBundle(build_system="yocto")

        # Machine and distro from local.conf
        bundle.yocto_machine = self._read_conf_var(build_dir, "MACHINE")
        bundle.yocto_distro = self._read_conf_var(build_dir, "DISTRO")

        tmp_dir = build_dir / "tmp"
        deploy_dir = tmp_dir / "deploy"

        # SBOM: prefer SPDX, fall back to cve-check manifest
        bundle.sbom, bundle.sbom_format = self._find_sbom(deploy_dir, build_dir)

        # Kernel .config
        bundle.kconfig = self._find_kconfig(tmp_dir)
        if bundle.kconfig:
            bundle.kernel_version = self._extract_kernel_version(bundle.kconfig)

        # DTBs
        bundle.dtb = self._find_dtbs(deploy_dir, bundle.yocto_machine, build_dir)

        # Busybox .config
        bundle.busybox_config = self._find_busybox_config(tmp_dir, build_dir)

        # PACKAGECONFIG (expensive — requires bitbake -e)
        bundle.packageconfigs = self._extract_packageconfigs(build_dir)

        # Cross-reference PACKAGECONFIG with CVE suppression maps
        for recipe, flags in bundle.packageconfigs.items():
            suppressed = lookup_suppressions(recipe, flags)
            if suppressed:
                bundle.packageconfig_suppressions[recipe] = suppressed

        logger.info("Yocto discovery: %s", bundle.summary())
        return bundle

    # ── Helpers ────────────────────────────────────────────────────────

    def _read_conf_var(self, build_dir: Path, var: str) -> str:
        """Read a variable from conf/local.conf (simple regex, not bitbake parser)."""
        local_conf = build_dir / "conf" / "local.conf"
        if not local_conf.exists():
            return ""
        try:
            text = local_conf.read_text()
            # Match: MACHINE = "raspberrypi4-64" or MACHINE ?= "..."
            match = re.search(rf'^{var}\s*\??=\s*"([^"]*)"', text, re.MULTILINE)
            return match.group(1) if match else ""
        except Exception:
            return ""

    def _find_sbom(self, deploy_dir: Path, build_dir: Path) -> tuple[Optional[Path], str]:
        """Find SBOM in deploy directory. Prefer SPDX over cve-check."""
        # SPDX output from create-spdx.bbclass
        spdx_dir = deploy_dir / "spdx"
        if spdx_dir.exists():
            spdx_files = sorted(spdx_dir.glob("*.spdx.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            for f in spdx_files:
                if self._validate_path(f, build_dir):
                    return f, "spdx"

        # CycloneDX (some Yocto setups generate this)
        cdx_files = sorted(deploy_dir.glob("**/*.cdx.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in cdx_files:
            if self._validate_path(f, build_dir):
                return f, "cyclonedx"

        # cve-check manifest
        cve_dir = deploy_dir / "cve"
        if cve_dir.exists():
            cve_files = sorted(cve_dir.glob("*.cve"), key=lambda p: p.stat().st_mtime, reverse=True)
            for f in cve_files:
                if self._validate_path(f, build_dir):
                    return f, "yocto-cve-check"

        return None, ""

    def _find_kconfig(self, tmp_dir: Path) -> Optional[Path]:
        """Find kernel .config from staging or work directory."""
        build_dir = tmp_dir.parent
        # Staging kernel dir (most reliable) — targeted glob to avoid
        # matching non-kernel .config files in large sysroots trees
        staging = tmp_dir / "sysroots-components"
        if staging.exists():
            for config in staging.glob("*/*linux*/.config"):
                if self._validate_path(config, build_dir):
                    return config

        # Work dir fallback
        work_dir = tmp_dir / "work"
        if work_dir.exists():
            for config in work_dir.glob("*/linux-*/*/build/.config"):
                if self._validate_path(config, build_dir):
                    return config

        return None

    def _extract_kernel_version(self, kconfig: Path) -> str:
        """Extract kernel version from .config header comment."""
        try:
            first_lines = kconfig.read_text()[:500]
            match = re.search(r"Linux/\w+ (\d+\.\d+\.\d+\S*) Kernel Configuration", first_lines)
            return match.group(1) if match else ""
        except Exception:
            return ""

    def _find_dtbs(self, deploy_dir: Path, machine: str, build_dir: Path) -> list[Path]:
        """Find DTB files in deploy directory."""
        image_dir = deploy_dir / "images" / machine if machine else deploy_dir / "images"
        if not image_dir.exists():
            # Try without machine subdirectory
            image_dir = deploy_dir / "images"
            if not image_dir.exists():
                return []

        dtbs = [p for p in image_dir.glob("*.dtb") if self._validate_path(p, build_dir)]
        # Also check for .dts source files
        dtbs.extend(p for p in image_dir.glob("*.dts") if self._validate_path(p, build_dir))
        # Cap DTB count to prevent excessive upload size. Most boards have 1-5 DTBs;
        # 20 covers multi-board images. Override via SCIATH_MAX_DTBS env var.
        max_dtbs = int(os.environ.get("SCIATH_MAX_DTBS", "20"))
        return dtbs[:max_dtbs]

    def _find_busybox_config(self, tmp_dir: Path, build_dir: Path) -> Optional[Path]:
        """Find busybox .config from work directory."""
        work_dir = tmp_dir / "work"
        if not work_dir.exists():
            return None

        for config in work_dir.glob("*/busybox/*/build/.config"):
            if self._validate_path(config, build_dir):
                return config
        # Alternative path in some Yocto versions
        for config in work_dir.glob("*/busybox-*/build/.config"):
            if self._validate_path(config, build_dir):
                return config

        return None

    def _extract_packageconfigs(self, build_dir: Path) -> dict[str, list[str]]:
        """
        Extract PACKAGECONFIG for key recipes via bitbake -e.

        This is expensive (~2s per recipe) so we only check recipes
        that have Sciath filter rules (openssl, curl, busybox, etc.).
        """
        env_recipes = os.environ.get("SCIATH_PACKAGECONFIG_RECIPES")
        if env_recipes:
            target_recipes = [r.strip() for r in env_recipes.split(",") if r.strip()]
        else:
            target_recipes = [
                "openssl", "curl", "busybox", "dbus", "systemd",
                "gstreamer1.0", "ffmpeg", "bluez5", "wpa-supplicant",
            ]

        configs: dict[str, list[str]] = {}
        for recipe in target_recipes:
            if not _RECIPE_NAME_RE.match(recipe):
                logger.warning("Skipping invalid recipe name: %r", recipe)
                continue
            flags = self._get_packageconfig(build_dir, recipe)
            if flags is not None:
                configs[recipe] = flags

        return configs

    def _get_packageconfig(self, build_dir: Path, recipe: str) -> Optional[list[str]]:
        """Get PACKAGECONFIG flags for a single recipe via bitbake -e."""
        try:
            result = subprocess.run(
                ["bitbake", "-e", recipe],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(build_dir),
            )
            if result.returncode != 0:
                return None

            for line in result.stdout.splitlines():
                if line.startswith("PACKAGECONFIG="):
                    # PACKAGECONFIG="flag1 flag2 flag3"
                    value = line.split("=", 1)[1].strip().strip('"')
                    return value.split() if value else []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None
