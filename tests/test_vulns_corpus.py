"""Tests for linux kernel vulns.git corpus loader."""

from pathlib import Path

import pytest

from sciath_cli.discovery.vulns_corpus import (
    VulnsIndex,
    build_index,
    load_index,
    save_index,
)


@pytest.fixture
def vulns_repo(tmp_path: Path) -> Path:
    """Synthetic vulns.git repo structure for testing."""
    published = tmp_path / "cve" / "published" / "2024"
    published.mkdir(parents=True)

    # .sha1 file — mainline fix commit (exactly 40 hex chars)
    (published / "CVE-2024-1234.sha1").write_text(
        "abc123def456abc123def456abc123def456abc1\n"
    )
    # .dyad file — branch-specific fixes for same CVE
    (published / "CVE-2024-1234.dyad").write_text(
        "# dyad version: test\n"
        "6.6.50:0000000000000000000000000000000000000000:6.6.55:111222333444555666777888999000aaabbbccc1\n"
    )

    # CVE with only .sha1
    (published / "CVE-2024-5678.sha1").write_text(
        "fedcba9876543210fedcba9876543210fedcba98\n"
    )

    # CVE with no fix (should be skipped)
    (published / "CVE-2024-9999.mbox").write_text(
        "Subject: reserved CVE, no fix yet\n"
    )

    # Init as git repo for commit hash
    import subprocess
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init", "--allow-empty"],
        cwd=str(tmp_path), capture_output=True,
        env={"GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"},
    )

    return tmp_path


class TestBuildIndex:
    def test_parses_sha1_file(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        fix = index.lookup("CVE-2024-1234")
        assert fix is not None
        assert fix.mainline_fix == "abc123def456abc123def456abc123def456abc1"

    def test_parses_dyad_branch_fixes(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        fix = index.lookup("CVE-2024-1234")
        assert fix is not None
        assert "6.6.55" in fix.branch_fixes

    def test_parses_sha1_only(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        fix = index.lookup("CVE-2024-5678")
        assert fix is not None
        assert fix.mainline_fix == "fedcba9876543210fedcba9876543210fedcba98"
        assert fix.branch_fixes == {}

    def test_skips_cve_without_fix(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        assert index.lookup("CVE-2024-9999") is None

    def test_total_count(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        assert index.total_cves == 2

    def test_get_fix_commits(self, vulns_repo: Path):
        index = build_index(vulns_repo)
        commits = index.get_fix_commits("CVE-2024-1234")
        assert "abc123def456abc123def456abc123def456abc1" in commits
        assert "111222333444555666777888999000aaabbbccc1" in commits


class TestIndexSerialization:
    def test_roundtrip(self, vulns_repo: Path, tmp_path: Path):
        index = build_index(vulns_repo)
        path = tmp_path / "index.json"
        save_index(index, path)

        loaded = load_index(path)
        assert loaded is not None
        assert loaded.total_cves == index.total_cves
        assert loaded.lookup("CVE-2024-1234") is not None

    def test_load_invalid(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        assert load_index(bad) is None

    def test_load_missing(self, tmp_path: Path):
        assert load_index(tmp_path / "nope.json") is None


class TestVulnsIndex:
    def test_empty_index(self):
        index = VulnsIndex()
        assert index.lookup("CVE-2024-0001") is None
        assert index.get_fix_commits("CVE-2024-0001") == []
