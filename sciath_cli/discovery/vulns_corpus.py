"""
Linux kernel CVE-to-commit mapping corpus.

Ingests the linux kernel vulns.git database
(git.kernel.org/pub/scm/linux/security/vulns.git/) which maps CVEs
to their fixing commits across kernel branches.

The corpus is pre-built as a local index (JSON) to avoid cloning on
every scan. The index maps CVE IDs to fixing commit hashes per branch.
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

VULNS_GIT_URL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"

# Each CVE file in vulns.git has a structured format with fix commits
# vulns.git file formats:
# .sha1 — single line with the mainline fix commit hash
# .dyad — pairs of vulnerable:fix per branch: vuln_ver:vuln_hash:fix_ver:fix_hash
# .mbox — email announcement (parsed for Subject line CVE reference)
_SHA1_RE = re.compile(r"^([0-9a-f]{40})\s*$")
_DYAD_LINE_RE = re.compile(
    r"^([^:]*):([0-9a-f]{40}):([^:]*):([0-9a-f]{40})\s*$"
)


@dataclass
class CveFix:
    """A CVE and its known fixing commits."""

    cve_id: str
    mainline_fix: str = ""  # Commit hash in mainline
    branch_fixes: dict[str, str] = field(default_factory=dict)  # branch → commit hash
    introduced_by: str = ""  # Commit that introduced the vulnerability


@dataclass
class VulnsIndex:
    """Pre-built index of CVE→commit mappings from vulns.git."""

    cve_fixes: dict[str, CveFix] = field(default_factory=dict)  # CVE ID → CveFix
    source_commit: str = ""  # vulns.git commit this was built from
    build_date: str = ""
    total_cves: int = 0

    def lookup(self, cve_id: str) -> Optional[CveFix]:
        return self.cve_fixes.get(cve_id)

    def get_fix_commits(self, cve_id: str) -> list[str]:
        """Get all known fix commit hashes for a CVE (mainline + branches)."""
        fix = self.cve_fixes.get(cve_id)
        if not fix:
            return []
        commits = []
        if fix.mainline_fix:
            commits.append(fix.mainline_fix)
        commits.extend(fix.branch_fixes.values())
        return commits

    def to_json(self) -> str:
        data: dict[str, Any] = {
            "source_commit": self.source_commit,
            "build_date": self.build_date,
            "total_cves": len(self.cve_fixes),
            "cves": {},
        }
        for cve_id, fix in self.cve_fixes.items():
            data["cves"][cve_id] = {
                "mainline_fix": fix.mainline_fix,
                "branch_fixes": fix.branch_fixes,
                "introduced_by": fix.introduced_by,
            }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "VulnsIndex":
        data = json.loads(text)
        index = cls(
            source_commit=data.get("source_commit", ""),
            build_date=data.get("build_date", ""),
        )
        for cve_id, fix_data in data.get("cves", {}).items():
            index.cve_fixes[cve_id] = CveFix(
                cve_id=cve_id,
                mainline_fix=fix_data.get("mainline_fix", ""),
                branch_fixes=fix_data.get("branch_fixes", {}),
                introduced_by=fix_data.get("introduced_by", ""),
            )
        index.total_cves = len(index.cve_fixes)
        return index


def build_index(vulns_repo_path: Path) -> VulnsIndex:
    """Build a VulnsIndex from a cloned vulns.git repository.

    Args:
        vulns_repo_path: Path to cloned vulns.git repo.

    Returns:
        VulnsIndex with all CVE→commit mappings.
    """
    from datetime import datetime, timezone

    index = VulnsIndex(build_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    index.source_commit = _get_git_commit(vulns_repo_path)

    # vulns.git structure: cve/<status>/YYYY/CVE-YYYY-NNNNN.<ext>
    # Status dirs: published, rejected, reserved, returned, review, testing
    # File types: .sha1 (mainline fix hash), .dyad (branch fix pairs), .mbox (announcement)
    cve_base = vulns_repo_path / "cve"
    if not cve_base.exists():
        logger.warning("No cve/ directory found in vulns repo at %s", vulns_repo_path)
        return index

    # Scan all status directories for CVE files
    for status_dir in sorted(cve_base.iterdir()):
        if not status_dir.is_dir() or status_dir.name in ("schema", "cvelistV5"):
            continue
        for year_dir in sorted(status_dir.iterdir()):
            if not year_dir.is_dir():
                continue
            # Group files by CVE ID (one CVE can have .sha1 + .dyad + .mbox)
            cve_files: dict[str, list[Path]] = {}
            for f in year_dir.iterdir():
                if not f.name.startswith("CVE-"):
                    continue
                # Extract CVE ID from filename (strip extensions like .sha1, .dyad, .mbox.rejected)
                cve_id = f.name.split(".")[0]
                if cve_id not in cve_files:
                    cve_files[cve_id] = []
                cve_files[cve_id].append(f)

            for cve_id, files in cve_files.items():
                cve_fix = _parse_cve_files(cve_id, files)
                if cve_fix:
                    # Merge with existing if we've seen this CVE in another status dir
                    if cve_id in index.cve_fixes:
                        existing = index.cve_fixes[cve_id]
                        if not existing.mainline_fix and cve_fix.mainline_fix:
                            existing.mainline_fix = cve_fix.mainline_fix
                        existing.branch_fixes.update(cve_fix.branch_fixes)
                    else:
                        index.cve_fixes[cve_id] = cve_fix

    index.total_cves = len(index.cve_fixes)
    logger.info("Built vulns index: %d CVEs with fix commits", index.total_cves)
    return index


def clone_vulns_repo(dest: Path, shallow: bool = True) -> Path:
    """Clone the linux kernel vulns.git repository.

    Args:
        dest: Directory to clone into.
        shallow: If True, use --depth=1 (sufficient for index building).

    Returns:
        Path to the cloned repo.
    """
    args = ["git", "clone"]
    if shallow:
        args.extend(["--depth=1"])
    args.extend([VULNS_GIT_URL, str(dest)])

    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to clone vulns.git: {result.stderr[:500]}")

    logger.info("Cloned vulns.git to %s", dest)
    return dest


def save_index(index: VulnsIndex, output_path: Path) -> None:
    """Save a VulnsIndex to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(index.to_json() + "\n")
    logger.info("Saved vulns index to %s (%d CVEs)", output_path, index.total_cves)


def load_index(index_path: Path) -> Optional[VulnsIndex]:
    """Load a VulnsIndex from a JSON file."""
    try:
        text = index_path.read_text()
        return VulnsIndex.from_json(text)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Cannot load vulns index %s: %s", index_path, e)
        return None


def _parse_cve_files(cve_id: str, files: list[Path]) -> Optional[CveFix]:
    """Parse CVE files from vulns.git (may be .sha1, .dyad, .mbox)."""
    fix = CveFix(cve_id=cve_id)

    for f in files:
        try:
            text = f.read_text(errors="replace").strip()
        except OSError:
            continue

        if f.name.endswith(".sha1"):
            # Single mainline fix commit hash
            match = _SHA1_RE.match(text)
            if match:
                fix.mainline_fix = match.group(1)

        elif ".dyad" in f.name:
            # Dyad format: vuln_ver:vuln_hash:fix_ver:fix_hash per line
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                match = _DYAD_LINE_RE.match(line)
                if match:
                    fix_version = match.group(3)
                    fix_hash = match.group(4)
                    if fix_version and fix_version != "0":
                        fix.branch_fixes[fix_version] = fix_hash
                    elif not fix.mainline_fix:
                        fix.mainline_fix = fix_hash

    # Only include CVEs with at least one fix commit
    if not fix.mainline_fix and not fix.branch_fixes:
        return None

    return fix


def _get_git_commit(path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, cwd=str(path),
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
