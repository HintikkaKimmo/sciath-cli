"""
Kernel fork analysis — enumerate vendor commits and match against CVE fixes.

For BSP vendors that maintain kernel forks (Toradex, PHYTEC, NXP), the
security-relevant patches are commits in the fork, not file:// patches.
This module clones the vendor fork, identifies the upstream base, and
matches vendor commits against the vulns.git corpus.
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sciath_cli.discovery.fingerprint import fingerprint_commits
from sciath_cli.discovery.vulns_corpus import VulnsIndex

logger = logging.getLogger(__name__)


@dataclass
class KernelForkAnalysis:
    """Results of analyzing a vendor kernel fork."""

    vendor: str
    fork_url: str
    fork_branch: str
    upstream_base: str = ""  # e.g., "v6.6.23"
    upstream_version: str = ""  # e.g., "6.6.23"
    vendor_commits: int = 0
    fingerprinted_commits: int = 0
    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    unmatched_commits: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def suppression_count(self) -> int:
        return len([m for m in self.cve_matches if m.get("confidence") == "high"])

    def summary(self) -> str:
        return (
            f"{self.vendor} kernel fork ({self.upstream_version}): "
            f"{self.vendor_commits} vendor commits, "
            f"{len(self.cve_matches)} CVE matches "
            f"({self.suppression_count} high confidence)"
        )


def analyze_kernel_fork(
    fork_path: Path,
    fork_branch: str,
    vendor: str,
    vulns_index: VulnsIndex,
    upstream_repo_path: Optional[Path] = None,
) -> KernelForkAnalysis:
    """Analyze a vendor kernel fork for CVE fix matches.

    Args:
        fork_path: Path to the cloned vendor kernel repo.
        fork_branch: Branch to analyze (e.g., "toradex_6.6-2.2.x").
        vendor: Vendor name for reporting.
        vulns_index: Pre-built CVE→commit index from vulns.git.
        upstream_repo_path: Optional path to upstream kernel for patch-id
            fingerprinting of fix commits. If None, uses commit hash
            matching only (no patch-id).

    Returns:
        KernelForkAnalysis with matches and statistics.
    """
    analysis = KernelForkAnalysis(
        vendor=vendor,
        fork_url="",
        fork_branch=fork_branch,
    )

    # Detect upstream base version from kernel Makefile
    version_info = _detect_upstream_base(fork_path)
    if version_info:
        analysis.upstream_version = version_info["version"]
        analysis.upstream_base = version_info.get("tag", "")
        logger.info("Detected upstream base: %s (tag: %s)",
                     analysis.upstream_version, analysis.upstream_base)
    else:
        analysis.warnings.append("Could not detect upstream kernel version from Makefile")
        return analysis

    # Find the upstream base tag in the fork repo
    base_tag = _find_base_tag(fork_path, analysis.upstream_version)
    if not base_tag:
        analysis.warnings.append(
            f"Could not find upstream tag for {analysis.upstream_version}. "
            "Trying version-based range."
        )
        # Fall back to commit-hash matching without fingerprinting
        return _analyze_by_commit_hash(fork_path, vendor, vulns_index, analysis)

    # Enumerate vendor commits (between base tag and HEAD)
    commit_range = f"{base_tag}..HEAD"
    vendor_fps = fingerprint_commits(fork_path, commit_range)
    analysis.vendor_commits = len(vendor_fps)
    analysis.fingerprinted_commits = len(vendor_fps)

    if not vendor_fps:
        analysis.warnings.append(f"No vendor commits found in range {commit_range}")
        return analysis

    # Build a quick lookup: all known fix commit hashes from vulns index
    fix_commit_hashes = _build_fix_hash_lookup(vulns_index)

    # Match vendor commits against known CVE fixes
    for fp in vendor_fps:
        # Method 1: direct commit hash match
        if fp.commit_hash in fix_commit_hashes:
            cve_id = fix_commit_hashes[fp.commit_hash]
            analysis.cve_matches.append({
                "cve_id": cve_id,
                "vendor_commit": fp.commit_hash[:12],
                "subject": fp.subject,
                "confidence": "high",
                "method": "commit_hash",
            })
            continue

        # Method 2: check subject line for CVE reference
        cve_in_subject = _extract_cve_from_subject(fp.subject)
        if cve_in_subject and cve_in_subject in vulns_index.cve_fixes:
            analysis.cve_matches.append({
                "cve_id": cve_in_subject,
                "vendor_commit": fp.commit_hash[:12],
                "subject": fp.subject,
                "confidence": "high",
                "method": "subject_cve_tag",
            })
            continue

        analysis.unmatched_commits += 1

    logger.info("Kernel fork analysis: %s", analysis.summary())
    return analysis


def clone_kernel_fork(
    repo_url: str,
    dest: Path,
    branch: str,
    shallow_since: str = "",
) -> Path:
    """Clone a vendor kernel fork with limited history.

    Args:
        repo_url: Git URL of the vendor kernel.
        dest: Directory to clone into.
        branch: Branch to clone.
        shallow_since: Date string for --shallow-since (e.g., "2024-01-01").
            If empty, uses --depth=500 as fallback.

    Returns:
        Path to cloned repo.
    """
    args = ["git", "clone", "--single-branch", f"--branch={branch}"]
    if shallow_since:
        args.append(f"--shallow-since={shallow_since}")
    else:
        args.extend(["--depth", "500"])
    args.extend([repo_url, str(dest)])

    logger.info("Cloning kernel fork %s branch %s...", repo_url, branch)
    result = subprocess.run(args, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to clone kernel fork: {result.stderr[:500]}")

    return dest


def _detect_upstream_base(repo_path: Path) -> Optional[dict[str, str]]:
    """Detect the upstream kernel version from the Makefile."""
    makefile = repo_path / "Makefile"
    if not makefile.exists():
        return None

    try:
        text = makefile.read_text()[:1000]
    except OSError:
        return None

    version_re = re.compile(r"^VERSION\s*=\s*(\d+)", re.MULTILINE)
    patchlevel_re = re.compile(r"^PATCHLEVEL\s*=\s*(\d+)", re.MULTILINE)
    sublevel_re = re.compile(r"^SUBLEVEL\s*=\s*(\d+)", re.MULTILINE)

    v = version_re.search(text)
    p = patchlevel_re.search(text)
    s = sublevel_re.search(text)

    if not (v and p):
        return None

    version = f"{v.group(1)}.{p.group(1)}"
    if s:
        version += f".{s.group(1)}"

    return {
        "version": version,
        "tag": f"v{version}",
    }


def _find_base_tag(repo_path: Path, version: str) -> Optional[str]:
    """Find the upstream base tag in the fork repo."""
    tag = f"v{version}"

    # Check if tag exists
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}"],
        capture_output=True, text=True, timeout=5, cwd=str(repo_path),
    )
    if result.returncode == 0:
        return tag

    # Try without sublevel (e.g., v6.6 instead of v6.6.23)
    parts = version.split(".")
    if len(parts) >= 3:
        short_tag = f"v{parts[0]}.{parts[1]}"
        result = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{short_tag}"],
            capture_output=True, text=True, timeout=5, cwd=str(repo_path),
        )
        if result.returncode == 0:
            return short_tag

    return None


def _build_fix_hash_lookup(vulns_index: VulnsIndex) -> dict[str, str]:
    """Build a commit_hash → CVE ID lookup from the vulns index.

    Maps both full and short (12-char) hashes for matching.
    """
    lookup: dict[str, str] = {}
    for cve_id, fix in vulns_index.cve_fixes.items():
        if fix.mainline_fix:
            lookup[fix.mainline_fix] = cve_id
            lookup[fix.mainline_fix[:12]] = cve_id
        for commit in fix.branch_fixes.values():
            lookup[commit] = cve_id
            lookup[commit[:12]] = cve_id
    return lookup


def _extract_cve_from_subject(subject: str) -> Optional[str]:
    """Extract a CVE ID from a commit subject line."""
    match = re.search(r"(CVE-\d{4}-\d{4,})", subject, re.IGNORECASE)
    return match.group(1).upper() if match else None


def _analyze_by_commit_hash(
    fork_path: Path,
    vendor: str,
    vulns_index: VulnsIndex,
    analysis: KernelForkAnalysis,
) -> KernelForkAnalysis:
    """Fallback: match vendor commits by hash and subject without fingerprinting.

    Used when the upstream base tag can't be found (no commit range).
    Walks recent commits and checks each against the vulns index.
    """
    try:
        result = subprocess.run(
            ["git", "log", "--format=%H %s", "-500"],
            capture_output=True, text=True, timeout=30, cwd=str(fork_path),
        )
        if result.returncode != 0:
            analysis.warnings.append("git log failed for fallback analysis")
            return analysis

        fix_hashes = _build_fix_hash_lookup(vulns_index)

        for line in result.stdout.strip().splitlines():
            parts = line.split(" ", 1)
            if len(parts) < 2:
                continue
            commit_hash, subject = parts[0], parts[1]
            analysis.vendor_commits += 1

            if commit_hash in fix_hashes or commit_hash[:12] in fix_hashes:
                cve_id = fix_hashes.get(commit_hash) or fix_hashes.get(commit_hash[:12], "")
                analysis.cve_matches.append({
                    "cve_id": cve_id,
                    "vendor_commit": commit_hash[:12],
                    "subject": subject,
                    "confidence": "high",
                    "method": "commit_hash",
                })
            else:
                cve_in_subject = _extract_cve_from_subject(subject)
                if cve_in_subject and cve_in_subject in vulns_index.cve_fixes:
                    analysis.cve_matches.append({
                        "cve_id": cve_in_subject,
                        "vendor_commit": commit_hash[:12],
                        "subject": subject,
                        "confidence": "high",
                        "method": "subject_cve_tag",
                    })
                else:
                    analysis.unmatched_commits += 1

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        analysis.warnings.append(f"Fallback analysis failed: {e}")

    return analysis
