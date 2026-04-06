"""Tests for build system detection across all discovery modules."""

from pathlib import Path

from sciath_cli.discovery.buildroot import BuildrootDiscovery
from sciath_cli.discovery.debian import DebianDiscovery
from sciath_cli.discovery.openwrt import OpenwrtDiscovery
from sciath_cli.discovery.yocto import YoctoDiscovery


class TestYoctoDetection:
    def test_detects_yocto(self, yocto_build_dir: Path):
        assert YoctoDiscovery().detect(yocto_build_dir) is True

    def test_rejects_empty_dir(self, tmp_build_dir: Path):
        assert YoctoDiscovery().detect(tmp_build_dir) is False

    def test_rejects_without_tmp(self, tmp_path: Path):
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text('MACHINE = "test"\n')
        assert YoctoDiscovery().detect(tmp_path) is False

    def test_rejects_without_local_conf(self, tmp_path: Path):
        (tmp_path / "tmp").mkdir()
        assert YoctoDiscovery().detect(tmp_path) is False


class TestBuildrootDetection:
    def test_detects_buildroot(self, buildroot_build_dir: Path):
        assert BuildrootDiscovery().detect(buildroot_build_dir) is True

    def test_rejects_empty_dir(self, tmp_build_dir: Path):
        assert BuildrootDiscovery().detect(tmp_build_dir) is False


class TestDebianDetection:
    def test_detects_debian(self, debian_build_dir: Path):
        assert DebianDiscovery().detect(debian_build_dir) is True

    def test_rejects_empty_dir(self, tmp_build_dir: Path):
        assert DebianDiscovery().detect(tmp_build_dir) is False


class TestOpenwrtDetection:
    def test_detects_openwrt(self, openwrt_build_dir: Path):
        assert OpenwrtDiscovery().detect(openwrt_build_dir) is True

    def test_rejects_empty_dir(self, tmp_build_dir: Path):
        assert OpenwrtDiscovery().detect(tmp_build_dir) is False

    def test_rejects_feeds_only(self, tmp_path: Path):
        (tmp_path / "feeds.conf").write_text("src-git ...\n")
        assert OpenwrtDiscovery().detect(tmp_path) is False
