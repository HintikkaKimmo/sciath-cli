"""Tests for Yocto artifact collection."""

from pathlib import Path
from unittest.mock import patch

from sciath_cli.discovery.yocto import YoctoDiscovery


class TestYoctoCollection:
    def test_collects_machine_and_distro(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.yocto_machine == "raspberrypi4-64"
        assert bundle.yocto_distro == "poky"

    def test_collects_sbom_spdx(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.has_sbom
        assert bundle.sbom_format == "spdx"
        assert bundle.sbom is not None
        assert bundle.sbom.name.endswith(".spdx.json")

    def test_collects_kconfig(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.has_kconfig
        assert bundle.kernel_version == "6.1.21"

    def test_collects_dtbs(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert len(bundle.dtb) == 2
        dtb_names = {p.name for p in bundle.dtb}
        assert "bcm2711-rpi-4-b.dtb" in dtb_names

    def test_collects_busybox_config(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.busybox_config is not None
        assert bundle.busybox_config.exists()

    def test_build_system_label(self, yocto_build_dir: Path):
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.build_system == "yocto"

    def test_sbom_prefers_spdx_over_cve(self, yocto_build_dir: Path):
        """SPDX should be preferred even when cve-check output exists."""
        cve_dir = yocto_build_dir / "tmp" / "deploy" / "cve"
        cve_dir.mkdir(parents=True)
        (cve_dir / "image.cve").write_text("CVE list")

        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.sbom_format == "spdx"

    def test_falls_back_to_cve_check(self, yocto_build_dir: Path):
        """When no SPDX, should pick up cve-check manifest."""
        # Remove SPDX
        spdx = yocto_build_dir / "tmp" / "deploy" / "spdx" / "image-raspberrypi4-64.spdx.json"
        spdx.unlink()

        # Add cve-check
        cve_dir = yocto_build_dir / "tmp" / "deploy" / "cve"
        cve_dir.mkdir(parents=True)
        (cve_dir / "image.cve").write_text("CVE list")

        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.sbom_format == "yocto-cve-check"

    def test_no_sbom(self, tmp_path: Path):
        """Minimal Yocto tree with no SBOM output."""
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text('MACHINE = "test"\n')
        (tmp_path / "tmp" / "deploy").mkdir(parents=True)

        bundle = YoctoDiscovery().collect(tmp_path)
        assert bundle.has_sbom is False
        assert bundle.sbom_format == ""

    def test_dtbs_without_machine_subdir(self, tmp_path: Path):
        """DTBs in deploy/images/ without machine subdirectory."""
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text("")
        (tmp_path / "tmp").mkdir()

        images_dir = tmp_path / "tmp" / "deploy" / "images"
        images_dir.mkdir(parents=True)
        (images_dir / "test.dtb").write_bytes(b"\x00")

        bundle = YoctoDiscovery().collect(tmp_path)
        assert len(bundle.dtb) == 1

    @patch("sciath_cli.discovery.yocto.subprocess.run")
    def test_packageconfig_extraction(self, mock_run, yocto_build_dir: Path):
        """PACKAGECONFIG parsed from bitbake -e output."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'PACKAGECONFIG="ssl zlib"\n'

        YoctoDiscovery().collect(yocto_build_dir)
        # Verify bitbake -e was called with correct arguments
        assert mock_run.call_count > 0, "subprocess.run should be called for PACKAGECONFIG"
        first_call = mock_run.call_args_list[0]
        cmd = first_call.args[0] if first_call.args else first_call.kwargs.get("args")
        assert cmd[0] == "bitbake", "command should invoke bitbake"
        assert cmd[1] == "-e", "bitbake should be called with -e flag"
        assert first_call.kwargs.get("cwd") == str(yocto_build_dir), "cwd should be build dir"
        assert first_call.kwargs.get("capture_output") is True
        assert first_call.kwargs.get("text") is True
        assert first_call.kwargs.get("timeout") == 30

    @patch("sciath_cli.discovery.yocto.subprocess.run", side_effect=FileNotFoundError)
    def test_packageconfig_without_bitbake(self, mock_run, yocto_build_dir: Path):
        """Gracefully handles missing bitbake command."""
        bundle = YoctoDiscovery().collect(yocto_build_dir)
        assert bundle.packageconfigs == {}


class TestYoctoConfParsing:
    def test_weak_assignment(self, tmp_path: Path):
        """Handles ?= (weak) assignment in local.conf."""
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text('MACHINE ?= "qemux86-64"\n')
        (tmp_path / "tmp").mkdir()

        bundle = YoctoDiscovery().collect(tmp_path)
        assert bundle.yocto_machine == "qemux86-64"

    def test_empty_local_conf(self, tmp_path: Path):
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "local.conf").write_text("")
        (tmp_path / "tmp").mkdir()

        bundle = YoctoDiscovery().collect(tmp_path)
        assert bundle.yocto_machine == ""
        assert bundle.yocto_distro == ""
