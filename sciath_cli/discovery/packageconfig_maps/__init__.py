"""
PACKAGECONFIG → CVE suppression mapping loader.

Each recipe has a JSON file mapping PACKAGECONFIG flags to CVE IDs
that are suppressed when that flag is active/inactive. The scan pipeline
uses these mappings to eliminate false positives from userspace packages.

Matching strategy:
- Primary: curated CVE ID lists per flag (high accuracy, manual maintenance)
- Secondary: CPE component matching against NVD (automatable, lower precision)
- Curated lists take priority over CPE matches.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_MAPS_DIR = Path(__file__).parent
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Cache loaded maps to avoid re-reading JSON on every call
_map_cache: dict[str, dict[str, Any]] = {}


def load_map(recipe: str) -> Optional[dict[str, Any]]:
    """Load the PACKAGECONFIG mapping for a recipe.

    Returns the parsed JSON dict, or None if the map doesn't exist
    or is invalid.
    """
    if recipe in _map_cache:
        return _map_cache[recipe]

    # Normalize recipe name for filename (e.g., wpa-supplicant → wpa_supplicant,
    # gstreamer1.0 → gstreamer1_0)
    filename = recipe.replace("-", "_").replace(".", "_") + ".json"
    map_path = _MAPS_DIR / filename

    if not map_path.exists():
        return None

    try:
        with open(map_path) as f:
            data: dict[str, Any] = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Invalid PACKAGECONFIG map for %s: %s", recipe, e)
        return None

    if not _validate_map(data, recipe):
        return None

    _map_cache[recipe] = data
    return data


def _validate_map(data: dict[str, Any], recipe: str) -> bool:
    """Validate the structure of a PACKAGECONFIG mapping file."""
    if not isinstance(data, dict):
        logger.warning("PACKAGECONFIG map for %s: expected dict, got %s", recipe, type(data).__name__)
        return False
    if "recipe" not in data or "flags" not in data:
        logger.warning("PACKAGECONFIG map for %s: missing 'recipe' or 'flags' key", recipe)
        return False
    if not isinstance(data["flags"], dict):
        logger.warning("PACKAGECONFIG map for %s: 'flags' must be a dict", recipe)
        return False

    # Validate CVE IDs in each flag
    for flag_name, flag_data in data["flags"].items():
        if not isinstance(flag_data, dict):
            continue
        for cve_id in flag_data.get("suppresses_cves", []):
            if not _CVE_ID_RE.match(cve_id):
                logger.warning(
                    "PACKAGECONFIG map for %s: invalid CVE ID %r in flag %s",
                    recipe, cve_id, flag_name,
                )
                return False

    return True


def lookup_suppressions(recipe: str, enabled_flags: list[str]) -> list[str]:
    """Look up which CVEs are suppressed given a recipe's enabled PACKAGECONFIG flags.

    Returns a list of CVE IDs that can be suppressed because the relevant
    feature is either disabled (flag not in enabled_flags) or enabled
    (flag in enabled_flags), depending on the mapping's effect type.

    Effect types:
      - feature_disabled: flag ABSENT means feature is compiled out → suppress
        (e.g., "ftp" not in PACKAGECONFIG → FTP protocol not built)
      - feature_enabled: flag PRESENT means hardening is active → suppress
        (e.g., "hardening" in PACKAGECONFIG → hardening mitigations active)
      - negated_flag: flag PRESENT means feature is disabled → suppress
        (e.g., "no-ssl3" in PACKAGECONFIG → SSL3 is compiled out)
    """
    mapping = load_map(recipe)
    if mapping is None:
        return []

    suppressed: list[str] = []
    enabled_set = set(enabled_flags)

    for flag_name, flag_data in mapping.get("flags", {}).items():
        if not isinstance(flag_data, dict):
            continue

        effect = flag_data.get("effect", "")
        cves = flag_data.get("suppresses_cves", [])

        if effect == "feature_disabled" and flag_name not in enabled_set:
            # Flag absent → feature is compiled out → CVEs don't apply
            suppressed.extend(cves)
        elif effect == "feature_enabled" and flag_name in enabled_set:
            # Flag present → hardening active → CVEs mitigated
            suppressed.extend(cves)
        elif effect == "negated_flag" and flag_name in enabled_set:
            # Flag present → feature is explicitly disabled → CVEs don't apply
            # Used for OpenSSL-style "no-ssl3", "no-comp" flags
            suppressed.extend(cves)

    return suppressed


def clear_cache() -> None:
    """Clear the map cache (useful for testing)."""
    _map_cache.clear()
