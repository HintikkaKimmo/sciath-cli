"""
Convert ArtifactBundle → scan API payload.

Bridge between the discovery module's output and the Sciath scan creation API.
Reads file contents from the bundle's paths, serializes PACKAGECONFIG
suppressions, and produces a dict ready to unpack into api.create_scan().
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from sciath_cli.discovery.base import ArtifactBundle


def bundle_to_payload(
    bundle: ArtifactBundle,
    project_id: str,
    version_label: str,
    policy_name: Optional[str] = None,
) -> dict[str, Any]:
    """Convert an ArtifactBundle to a scan creation API payload.

    Returns a dict with keys matching SciathAPI.create_scan() parameters.
    File contents are read from the paths in the bundle.
    """
    sbom_raw = ""
    sbom_format = ""
    if bundle.has_sbom:
        assert bundle.sbom is not None
        sbom_raw = bundle.sbom.read_text(errors="replace")
        sbom_format = _normalize_sbom_format(bundle.sbom_format, bundle.sbom, sbom_raw)

    kconfig_raw = ""
    if bundle.has_kconfig:
        assert bundle.kconfig is not None
        kconfig_raw = bundle.kconfig.read_text(errors="replace")

    dtb_raw = ""
    if bundle.dtb:
        parts = []
        for dtb_path in bundle.dtb:
            if dtb_path.exists():
                parts.append(dtb_path.read_text(errors="replace"))
        dtb_raw = "\n".join(parts)

    custom_filter_raw = ""
    if not policy_name:
        custom_filter_raw = _build_custom_filter(bundle)

    idem_input = f"{project_id}:{version_label}:{sbom_raw}"
    idempotency_key = hashlib.sha256(idem_input.encode()).hexdigest()[:32]

    payload: dict[str, Any] = {
        "project_id": project_id,
        "version_label": version_label,
        "sbom_raw": sbom_raw,
        "sbom_format": sbom_format,
        "kconfig_raw": kconfig_raw,
        "idempotency_key": idempotency_key,
    }

    if dtb_raw:
        payload["dtb_raw"] = dtb_raw
    if policy_name:
        payload["policy_name"] = policy_name
    elif custom_filter_raw:
        payload["custom_filter_raw"] = custom_filter_raw
    if bundle.yocto_machine:
        payload["yocto_machine"] = bundle.yocto_machine
    if bundle.yocto_distro:
        payload["yocto_distro"] = bundle.yocto_distro
    if bundle.kernel_version:
        payload["kernel_version"] = bundle.kernel_version

    return payload


def _normalize_sbom_format(declared: str, path: Path, content: str) -> str:
    """Normalize SBOM format string to what the API expects."""
    lower = declared.lower().strip()
    if lower in ("spdx", "cyclonedx", "yocto_manifest", "yocto-manifest"):
        return lower.replace("-", "_")

    name = path.name.lower()
    if "spdx" in name or '"spdxVersion"' in content:
        return "spdx"
    if "yocto" in name or name.endswith(".manifest"):
        return "yocto_manifest"
    return "cyclonedx"


def _build_custom_filter(bundle: ArtifactBundle) -> str:
    """Build a custom filter JSON from PACKAGECONFIG suppressions.

    Returns empty string if there's nothing to include.
    """
    rules: list[dict[str, Any]] = []

    for recipe, cve_ids in bundle.packageconfig_suppressions.items():
        for cve_id in cve_ids:
            rules.append({
                "type": "packageconfig",
                "cve_id": cve_id,
                "component": recipe,
                "justification": f"PACKAGECONFIG for {recipe} disables affected feature",
                "confidence": "medium",
                "source": "sciath-discovery",
            })

    if not rules:
        return ""

    filter_doc = {
        "schema_version": "1.0",
        "source": "sciath-discovery",
        "build_system": bundle.build_system,
        "rules": rules,
    }
    return json.dumps(filter_doc, separators=(",", ":"))
