"""
Local input cache for scan results.

Hashes the input files (SBOM + kconfig + DTB) and project ID. If the hash
matches a recent scan, returns the cached scan ID to skip re-upload.

Cache stored at ~/.sciath/cache/ with TTL (default 1 hour).
"""

import hashlib
import json
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".sciath" / "cache"
DEFAULT_TTL = 3600  # 1 hour


def _cache_key(project_id: str, sbom_raw: str, kconfig_raw: str, dtb_raw: str) -> str:
    """Compute a cache key from input content."""
    content = f"{project_id}:{sbom_raw}:{kconfig_raw}:{dtb_raw}"
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def get_cached_scan(project_id: str, sbom_raw: str, kconfig_raw: str = "", dtb_raw: str = "") -> str | None:
    """
    Check if a scan with matching inputs was recently uploaded.

    Returns scan_id if cache hit, None if miss or expired.
    """
    key = _cache_key(project_id, sbom_raw, kconfig_raw, dtb_raw)
    cache_file = CACHE_DIR / f"{key}.json"

    if not cache_file.exists():
        return None

    try:
        data = json.loads(cache_file.read_text())
        if time.time() - data.get("timestamp", 0) > DEFAULT_TTL:
            cache_file.unlink(missing_ok=True)
            return None
        return data.get("scan_id")
    except (json.JSONDecodeError, OSError):
        cache_file.unlink(missing_ok=True)
        return None


def save_cache(project_id: str, sbom_raw: str, kconfig_raw: str, dtb_raw: str, scan_id: str) -> None:
    """Save a scan result to the local cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(project_id, sbom_raw, kconfig_raw, dtb_raw)
    cache_file = CACHE_DIR / f"{key}.json"

    data = {
        "scan_id": scan_id,
        "project_id": project_id,
        "timestamp": time.time(),
    }
    cache_file.write_text(json.dumps(data))
