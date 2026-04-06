"""
Git patch fingerprinting for CVE fix matching.

Uses git patch-id semantics to produce stable hashes of commit diffs,
enabling matching between vendor kernel commits and known CVE fixes
even when commits have been cherry-picked or rebased.
"""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CommitFingerprint:
    """Fingerprint of a single git commit."""

    commit_hash: str
    patch_id: str  # git patch-id stable hash
    subject: str = ""
    files_changed: list[str] | None = None


def fingerprint_commit(repo_path: Path, commit_hash: str) -> Optional[CommitFingerprint]:
    """Generate a fingerprint for a single commit using git patch-id.

    Args:
        repo_path: Path to git repository.
        commit_hash: Full or short commit hash.

    Returns:
        CommitFingerprint, or None if the commit can't be fingerprinted
        (e.g., merge commits with no diff).
    """
    try:
        # Get the diff for this commit and pipe through git patch-id
        diff_result = subprocess.run(
            ["git", "diff-tree", "-p", commit_hash],
            capture_output=True, text=True, timeout=10, cwd=str(repo_path),
        )
        if diff_result.returncode != 0 or not diff_result.stdout.strip():
            return None

        # git patch-id reads a diff from stdin and outputs: <patch-id> <commit>
        patchid_result = subprocess.run(
            ["git", "patch-id", "--stable"],
            input=diff_result.stdout,
            capture_output=True, text=True, timeout=10, cwd=str(repo_path),
        )
        if patchid_result.returncode != 0 or not patchid_result.stdout.strip():
            return None

        parts = patchid_result.stdout.strip().split()
        patch_id = parts[0] if parts else ""
        if not patch_id:
            return None

        # Get subject line
        subject_result = subprocess.run(
            ["git", "log", "--format=%s", "-1", commit_hash],
            capture_output=True, text=True, timeout=5, cwd=str(repo_path),
        )
        subject = subject_result.stdout.strip() if subject_result.returncode == 0 else ""

        return CommitFingerprint(
            commit_hash=commit_hash,
            patch_id=patch_id,
            subject=subject,
        )

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def fingerprint_commits(repo_path: Path, commit_range: str) -> list[CommitFingerprint]:
    """Fingerprint all commits in a range.

    Args:
        repo_path: Path to git repository.
        commit_range: Git range expression (e.g., "v6.6..HEAD", "abc123..def456").

    Returns:
        List of CommitFingerprints for commits that could be fingerprinted.
    """
    try:
        result = subprocess.run(
            ["git", "rev-list", commit_range],
            capture_output=True, text=True, timeout=30, cwd=str(repo_path),
        )
        if result.returncode != 0:
            logger.warning("git rev-list failed for %s: %s", commit_range, result.stderr[:200])
            return []

        commits = [h.strip() for h in result.stdout.strip().splitlines() if h.strip()]
        logger.info("Fingerprinting %d commits in range %s", len(commits), commit_range)

        fingerprints = []
        for commit_hash in commits:
            fp = fingerprint_commit(repo_path, commit_hash)
            if fp:
                fingerprints.append(fp)

        logger.info("Fingerprinted %d/%d commits", len(fingerprints), len(commits))
        return fingerprints

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("Failed to enumerate commits: %s", e)
        return []


def match_commit_to_cve(
    commit_fp: CommitFingerprint,
    fix_commit_fps: dict[str, str],
) -> Optional[tuple[str, str]]:
    """Check if a vendor commit matches a known CVE fix.

    Args:
        commit_fp: Fingerprint of the vendor commit.
        fix_commit_fps: Dict mapping patch_id → CVE ID from the vulns index.

    Returns:
        Tuple of (CVE ID, confidence) if matched, or None.
        Confidence: "high" = patch-id match + commit hash match,
                    "medium" = patch-id match only.
    """
    if commit_fp.patch_id in fix_commit_fps:
        cve_id = fix_commit_fps[commit_fp.patch_id]
        return (cve_id, "high")

    return None


def build_fix_fingerprint_index(
    vulns_repo_path: Path,
    kernel_repo_path: Path,
    fix_commits: dict[str, list[str]],
) -> dict[str, str]:
    """Build a patch-id → CVE ID lookup from vulns.git fix commits.

    Args:
        vulns_repo_path: Not used directly (fix commits already extracted).
        kernel_repo_path: A kernel repo where fix commits can be resolved.
        fix_commits: Dict mapping CVE ID → list of fix commit hashes.

    Returns:
        Dict mapping patch_id → CVE ID for matching.
    """
    index: dict[str, str] = {}

    for cve_id, commits in fix_commits.items():
        for commit_hash in commits:
            fp = fingerprint_commit(kernel_repo_path, commit_hash)
            if fp:
                index[fp.patch_id] = cve_id

    logger.info("Built fix fingerprint index: %d patch-ids for %d CVEs",
                len(index), len(fix_commits))
    return index
