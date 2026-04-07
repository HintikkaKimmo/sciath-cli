"""Tests for sciath_cli.discovery.submit — ArtifactBundle → scan API payload."""

import json
from pathlib import Path

import pytest

from sciath_cli.discovery.base import ArtifactBundle
from sciath_cli.discovery.submit import bundle_to_payload


@pytest.fixture
def tmp_sbom(tmp_path: Path) -> Path:
    sbom = tmp_path / "sbom.spdx.json"
    sbom.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}')
    return sbom


@pytest.fixture
def tmp_kconfig(tmp_path: Path) -> Path:
    cfg = tmp_path / ".config"
    cfg.write_text("# Linux kernel config\nCONFIG_BT=n\nCONFIG_USB=y\n")
    return cfg


class TestBundleToPayload:
    def test_minimal_bundle(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx", build_system="yocto")
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")

        assert payload["project_id"] == "proj-1"
        assert payload["version_label"] == "v1.0"
        assert payload["sbom_format"] == "spdx"
        assert '"spdxVersion"' in payload["sbom_raw"]
        assert payload["kconfig_raw"] == ""
        assert "dtb_raw" not in payload
        assert len(payload["idempotency_key"]) == 32

    def test_full_bundle(self, tmp_sbom: Path, tmp_kconfig: Path, tmp_path: Path) -> None:
        dtb = tmp_path / "board.dts"
        dtb.write_text("/dts-v1/;\n/ { model = \"Board\"; };")

        bundle = ArtifactBundle(
            sbom=tmp_sbom, sbom_format="spdx", kconfig=tmp_kconfig,
            dtb=[dtb], yocto_machine="imx6", yocto_distro="poky",
            kernel_version="6.1.77", build_system="yocto",
        )
        payload = bundle_to_payload(bundle, "proj-1", "v2.0")

        assert "CONFIG_BT=n" in payload["kconfig_raw"]
        assert "Board" in payload["dtb_raw"]
        assert payload["yocto_machine"] == "imx6"
        assert payload["kernel_version"] == "6.1.77"

    def test_empty_bundle(self) -> None:
        bundle = ArtifactBundle(build_system="yocto")
        payload = bundle_to_payload(bundle, "proj-1", "v0.1")
        assert payload["sbom_raw"] == ""
        assert "dtb_raw" not in payload

    def test_policy_name_excludes_custom_filter(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom, sbom_format="spdx",
            packageconfig_suppressions={"openssl": ["CVE-2023-0001"]},
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0", policy_name="Auto Base")
        assert payload["policy_name"] == "Auto Base"
        assert "custom_filter_raw" not in payload

    def test_idempotency_key_deterministic(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        p1 = bundle_to_payload(bundle, "proj-1", "v1.0")
        p2 = bundle_to_payload(bundle, "proj-1", "v1.0")
        assert p1["idempotency_key"] == p2["idempotency_key"]

    def test_idempotency_key_changes_with_version(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        p1 = bundle_to_payload(bundle, "proj-1", "v1.0")
        p2 = bundle_to_payload(bundle, "proj-1", "v2.0")
        assert p1["idempotency_key"] != p2["idempotency_key"]


class TestPackageConfigSuppression:
    def test_packageconfig_rules_in_custom_filter(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(
            sbom=tmp_sbom, sbom_format="spdx", build_system="yocto",
            packageconfig_suppressions={
                "openssl": ["CVE-2023-0001", "CVE-2023-0002"],
                "curl": ["CVE-2023-1000"],
            },
        )
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")
        doc = json.loads(payload["custom_filter_raw"])

        assert doc["schema_version"] == "1.0"
        assert len(doc["rules"]) == 3
        cve_ids = {r["cve_id"] for r in doc["rules"]}
        assert cve_ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-1000"}

    def test_no_suppressions_no_custom_filter(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="spdx")
        payload = bundle_to_payload(bundle, "proj-1", "v1.0")
        assert "custom_filter_raw" not in payload


class TestSbomFormatNormalization:
    def test_yocto_manifest_hyphen_normalized(self, tmp_sbom: Path) -> None:
        bundle = ArtifactBundle(sbom=tmp_sbom, sbom_format="yocto-manifest")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "yocto_manifest"

    def test_fallback_detection_spdx(self, tmp_path: Path) -> None:
        sbom = tmp_path / "output.spdx.json"
        sbom.write_text('{"spdxVersion": "SPDX-2.3"}')
        bundle = ArtifactBundle(sbom=sbom, sbom_format="unknown")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "spdx"

    def test_fallback_detection_cyclonedx(self, tmp_path: Path) -> None:
        sbom = tmp_path / "bom.json"
        sbom.write_text('{"bomFormat": "CycloneDX"}')
        bundle = ArtifactBundle(sbom=sbom, sbom_format="")
        payload = bundle_to_payload(bundle, "p", "v")
        assert payload["sbom_format"] == "cyclonedx"
