"""Tests for path traversal safety."""

from pathlib import Path

from sciath_cli.discovery.base import ArtifactBundle, BuildSystemDiscovery


class ConcreteDiscovery(BuildSystemDiscovery):
    """Minimal concrete subclass for testing _validate_path."""

    def detect(self, build_dir: Path) -> bool:
        return False

    def collect(self, build_dir: Path) -> ArtifactBundle:
        return ArtifactBundle()


class TestPathSafety:
    def test_valid_path_within_build_dir(self, tmp_path: Path):
        child = tmp_path / "sub" / "file.txt"
        child.parent.mkdir(parents=True)
        child.write_text("test")
        assert ConcreteDiscovery()._validate_path(child, tmp_path) is True

    def test_rejects_path_outside_build_dir(self, tmp_path: Path):
        outside = tmp_path.parent / "outside.txt"
        assert ConcreteDiscovery()._validate_path(outside, tmp_path) is False

    def test_rejects_traversal_attack(self, tmp_path: Path):
        traversal = tmp_path / "sub" / ".." / ".." / "etc" / "passwd"
        assert ConcreteDiscovery()._validate_path(traversal, tmp_path) is False

    def test_build_dir_itself_is_valid(self, tmp_path: Path):
        assert ConcreteDiscovery()._validate_path(tmp_path, tmp_path) is True

    def test_rejects_symlink_escape(self, tmp_path: Path):
        """Symlinks pointing outside build_dir must be rejected."""
        outside = tmp_path.parent / "secret.txt"
        outside.write_text("sensitive")
        link = tmp_path / "link_to_secret"
        link.symlink_to(outside)
        assert ConcreteDiscovery()._validate_path(link, tmp_path) is False
