"""Tests for BSP ingestion orchestrator."""

import json
from pathlib import Path

import pytest

from sciath_cli.discovery.bsp_ingest import (
    BspProfile,
    check_staleness,
    ingest_bsp,
    load_profile,
    save_profile,
)


@pytest.fixture
def bsp_layer(tmp_path: Path) -> Path:
    """BSP layer with kernel recipe, patches, and config fragments."""
    layer = tmp_path / "meta-testbsp"
    layer.mkdir()

    conf = layer / "conf"
    conf.mkdir()
    (conf / "layer.conf").write_text(
        'BBFILE_COLLECTIONS += "meta-testbsp"\n'
        'BBFILE_PRIORITY_meta-testbsp = "7"\n'
    )

    # Kernel recipe
    kernel_dir = layer / "recipes-kernel" / "linux"
    kernel_dir.mkdir(parents=True)
    (kernel_dir / "linux-testbsp_5.15.bb").write_text(
        'SRC_URI = "git://kernel.org;branch=main \\\n'
        '           file://CVE-2024-1234.patch \\\n'
        '           file://0001-vendor-fix.patch \\\n'
        '           "\n'
    )

    patches_dir = kernel_dir / "linux-testbsp"
    patches_dir.mkdir()
    (patches_dir / "CVE-2024-1234.patch").write_text(
        "Subject: fix CVE-2024-1234\n"
        "Upstream-Status: Backport\n"
        "CVE: CVE-2024-1234\n"
        "\n--- a/file.c\n+++ b/file.c\n"
    )
    (patches_dir / "0001-vendor-fix.patch").write_text(
        "Subject: vendor specific DTS fix\n"
        "Upstream-Status: Inappropriate [vendor specific]\n"
        "\n--- a/arch/arm64/boot/dts/vendor.dts\n"
    )

    # Kernel config fragments
    (patches_dir / "security.cfg").write_text(
        "CONFIG_SECURITY=y\n"
        "CONFIG_SECCOMP=y\n"
        "# CONFIG_MODULES is not set\n"
    )
    (patches_dir / "network.cfg").write_text(
        "CONFIG_NET=y\n"
        "CONFIG_INET=y\n"
    )

    return layer


class TestIngestBsp:
    def test_basic_ingestion(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        assert profile.vendor == "testvendor"
        assert profile.som == "test-board"
        assert len(profile.patches) == 2

    def test_cve_suppression_generated(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        cve_ids = [s["cve_id"] for s in profile.suppressions]
        assert "CVE-2024-1234" in cve_ids

    def test_suppression_confidence(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        cve_suppression = [s for s in profile.suppressions if s["cve_id"] == "CVE-2024-1234"][0]
        assert cve_suppression["confidence"] == "high"  # Backport status
        assert "Backport" in cve_suppression["evidence"]

    def test_patch_classification(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        classifications = {p["file"]: p["classification"] for p in profile.patches}
        assert classifications["CVE-2024-1234.patch"] == "cve-tagged"
        assert classifications["0001-vendor-fix.patch"] == "vendor-only"

    def test_kconfig_merged(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        assert profile.kernel_config["CONFIG_SECURITY"] == "y"
        assert profile.kernel_config["CONFIG_NET"] == "y"
        assert profile.kernel_config["CONFIG_MODULES"] == "n"

    def test_parse_confidence(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        assert profile.parse_confidence == 1.0

    def test_analyzed_date_set(self, bsp_layer: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        assert profile.analyzed_date  # Non-empty


class TestSaveLoadProfile:
    def test_roundtrip(self, bsp_layer: Path, tmp_path: Path):
        profile = ingest_bsp(bsp_layer, vendor="testvendor", som="test-board")
        output_dir = tmp_path / "bsp_data"
        path = save_profile(profile, output_dir)
        assert path.exists()

        loaded = load_profile(path)
        assert loaded is not None
        assert loaded.vendor == "testvendor"
        assert loaded.som == "test-board"
        assert len(loaded.patches) == len(profile.patches)
        assert len(loaded.suppressions) == len(profile.suppressions)

    def test_filename_normalized(self, bsp_layer: Path, tmp_path: Path):
        profile = ingest_bsp(bsp_layer, vendor="toradex", som="verdin-imx8mp")
        path = save_profile(profile, tmp_path)
        assert path.name == "toradex_verdin_imx8mp.json"

    def test_load_invalid_json(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json")
        assert load_profile(bad_file) is None

    def test_load_missing_file(self, tmp_path: Path):
        assert load_profile(tmp_path / "nonexistent.json") is None


class TestStaleness:
    def test_same_commit_not_stale(self):
        profile = BspProfile(vendor="test", som="board", bsp_repo="", analyzed_commit="abc123")
        # Can't easily test without a real git repo, so test the None case
        warning = check_staleness(profile, Path("/nonexistent"))
        assert warning is None  # Can't determine, don't warn

    def test_no_commit_info(self):
        profile = BspProfile(vendor="test", som="board", bsp_repo="", analyzed_commit="")
        warning = check_staleness(profile, Path("/tmp"))
        assert warning is None


class TestBspProfileSerialization:
    def test_to_json(self):
        profile = BspProfile(
            vendor="toradex",
            som="verdin-imx8mp",
            bsp_repo="https://github.com/toradex/meta-toradex",
            patches=[{"recipe": "linux", "file": "fix.patch", "cve_ids": ["CVE-2024-1234"], "classification": "cve-tagged"}],
            suppressions=[{"cve_id": "CVE-2024-1234", "reason": "patch", "confidence": "high", "evidence": "test"}],
            kernel_config={"CONFIG_USB": "y"},
        )
        text = profile.to_json()
        data = json.loads(text)
        assert data["vendor"] == "toradex"
        assert len(data["patches"]) == 1
        assert data["kernel_config"]["CONFIG_USB"] == "y"

    def test_from_json_roundtrip(self):
        profile = BspProfile(vendor="test", som="board", bsp_repo="https://example.com")
        text = profile.to_json()
        loaded = BspProfile.from_json(text)
        assert loaded.vendor == profile.vendor
        assert loaded.som == profile.som
