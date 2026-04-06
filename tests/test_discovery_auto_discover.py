"""Tests for auto_discover() dispatch logic."""

from pathlib import Path

import pytest

from sciath_cli.discovery import auto_discover


class TestAutoDiscover:
    def test_auto_detects_yocto(self, yocto_build_dir: Path):
        bundle = auto_discover(str(yocto_build_dir))
        assert bundle.build_system == "yocto"

    def test_explicit_build_system(self, yocto_build_dir: Path):
        bundle = auto_discover(str(yocto_build_dir), build_system="yocto")
        assert bundle.build_system == "yocto"

    def test_unknown_build_system_raises(self, tmp_build_dir: Path):
        with pytest.raises(ValueError, match="Unknown build system"):
            auto_discover(str(tmp_build_dir), build_system="fakesystem")

    def test_no_detection_raises(self, tmp_build_dir: Path):
        with pytest.raises(RuntimeError, match="Could not detect"):
            auto_discover(str(tmp_build_dir))

    def test_nonexistent_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            auto_discover("/nonexistent/path/xyz")

    def test_stub_build_systems_raise_not_implemented(
        self, buildroot_build_dir: Path, debian_build_dir: Path, openwrt_build_dir: Path
    ):
        with pytest.raises(NotImplementedError):
            auto_discover(str(buildroot_build_dir), build_system="buildroot")
        with pytest.raises(NotImplementedError):
            auto_discover(str(debian_build_dir), build_system="debian")
        with pytest.raises(NotImplementedError):
            auto_discover(str(openwrt_build_dir), build_system="openwrt")
