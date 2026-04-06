"""Tests for discovery base classes."""

from pathlib import Path

from sciath_cli.discovery.base import ArtifactBundle


class TestArtifactBundle:
    def test_defaults(self):
        bundle = ArtifactBundle()
        assert bundle.sbom is None
        assert bundle.kconfig is None
        assert bundle.dtb == []
        assert bundle.packageconfigs == {}
        assert bundle.build_system == ""

    def test_has_sbom_with_existing_file(self, tmp_path: Path):
        sbom = tmp_path / "test.spdx.json"
        sbom.write_text("{}")
        bundle = ArtifactBundle(sbom=sbom, sbom_format="spdx")
        assert bundle.has_sbom is True

    def test_has_sbom_without_file(self):
        bundle = ArtifactBundle(sbom=Path("/nonexistent"))
        assert bundle.has_sbom is False

    def test_has_sbom_none(self):
        bundle = ArtifactBundle()
        assert bundle.has_sbom is False

    def test_has_kconfig_with_existing_file(self, tmp_path: Path):
        kconfig = tmp_path / ".config"
        kconfig.write_text("CONFIG_ARM64=y\n")
        bundle = ArtifactBundle(kconfig=kconfig)
        assert bundle.has_kconfig is True

    def test_artifact_count(self, tmp_path: Path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        kconfig = tmp_path / ".config"
        kconfig.write_text("CONFIG=y\n")
        dtb = tmp_path / "test.dtb"
        dtb.write_bytes(b"\x00")

        bundle = ArtifactBundle(
            sbom=sbom,
            sbom_format="spdx",
            kconfig=kconfig,
            dtb=[dtb],
            packageconfigs={"openssl": ["no-weak-ssl"]},
        )
        assert bundle.artifact_count == 4

    def test_artifact_count_empty(self):
        assert ArtifactBundle().artifact_count == 0

    def test_summary_with_artifacts(self, tmp_path: Path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        bundle = ArtifactBundle(
            sbom=sbom,
            sbom_format="spdx",
            dtb=[tmp_path / "a.dtb"],
            build_system="yocto",
        )
        summary = bundle.summary()
        assert "SBOM (spdx)" in summary
        assert "1 DTB(s)" in summary
        assert "[yocto]" in summary

    def test_summary_empty(self):
        assert ArtifactBundle().summary() == "No artifacts found"
