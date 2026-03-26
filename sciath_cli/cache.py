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


def _cache_key(
    project_id: str,
    sbom_raw: str,
    kconfig_raw: str,
    dtb_raw: str,
    custom_filter_raw: str = "",
) -> str:
    """Compute a cache key from input content."""
    content = f"{project_id}:{sbom_raw}:{kconfig_raw}:{dtb_raw}:{custom_filter_raw}"
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def get_cached_scan(
    project_id: str,
    sbom_raw: str,
    kconfig_raw: str = "",
    dtb_raw: str = "",
    custom_filter_raw: str = "",
) -> str | None:
    """
    Check if a scan with matching inputs was recently uploaded.

    Returns scan_id if cache hit, None if miss or expired.
    """
    key = _cache_key(project_id, sbom_raw, kconfig_raw, dtb_raw, custom_filter_raw)
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


def save_cache(
    project_id: str,
    sbom_raw: str,
    kconfig_raw: str,
    dtb_raw: str,
    scan_id: str,
    custom_filter_raw: str = "",
) -> None:
    """Save a scan result to the local cache. Also cleans up expired entries."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(project_id, sbom_raw, kconfig_raw, dtb_raw, custom_filter_raw)
    cache_file = CACHE_DIR / f"{key}.json"

    data = {
        "scan_id": scan_id,
        "project_id": project_id,
        "timestamp": time.time(),
    }
    cache_file.write_text(json.dumps(data))

    # Opportunistic cleanup of expired cache entries
    _cleanup_expired()


def _cleanup_expired() -> int:
    """Remove expired cache files. Returns count of files removed."""
    if not CACHE_DIR.exists():
        return 0

    now = time.time()
    removed = 0
    for f in CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if now - data.get("timestamp", 0) > DEFAULT_TTL:
                f.unlink(missing_ok=True)
                removed += 1
        except (json.JSONDecodeError, OSError):
            f.unlink(missing_ok=True)
            removed += 1
    return removed


def clear_all() -> int:
    """Remove all cache files. Returns count of files removed."""
    if not CACHE_DIR.exists():
        return 0

    removed = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink(missing_ok=True)
        removed += 1
    return removed
