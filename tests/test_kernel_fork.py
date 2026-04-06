"""Tests for kernel fork analysis."""

from pathlib import Path

from sciath_cli.discovery.kernel_fork import (
    KernelForkAnalysis,
    _detect_upstream_base,
    _extract_cve_from_subject,
)


class TestDetectUpstreamBase:
    def test_full_version(self, tmp_path: Path):
        makefile = tmp_path / "Makefile"
        makefile.write_text(
            "# SPDX-License-Identifier: GPL-2.0\n"
            "VERSION = 6\n"
            "PATCHLEVEL = 6\n"
            "SUBLEVEL = 23\n"
            "EXTRAVERSION =\n"
        )
        result = _detect_upstream_base(tmp_path)
        assert result is not None
        assert result["version"] == "6.6.23"
        assert result["tag"] == "v6.6.23"

    def test_version_without_sublevel(self, tmp_path: Path):
        makefile = tmp_path / "Makefile"
        makefile.write_text("VERSION = 6\nPATCHLEVEL = 6\n")
        result = _detect_upstream_base(tmp_path)
        assert result is not None
        assert result["version"] == "6.6"

    def test_no_makefile(self, tmp_path: Path):
        assert _detect_upstream_base(tmp_path) is None

    def test_invalid_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text("not a kernel makefile\n")
        assert _detect_upstream_base(tmp_path) is None


class TestExtractCveFromSubject:
    def test_cve_in_subject(self):
        assert _extract_cve_from_subject("fix CVE-2024-1234 in usb") == "CVE-2024-1234"

    def test_no_cve(self):
        assert _extract_cve_from_subject("fix usb null deref") is None

    def test_case_insensitive(self):
        assert _extract_cve_from_subject("fix cve-2024-5678") == "CVE-2024-5678"


class TestKernelForkAnalysis:
    def test_summary(self):
        analysis = KernelForkAnalysis(
            vendor="toradex",
            fork_url="git://git.toradex.com/linux-toradex.git",
            fork_branch="toradex_6.6",
            upstream_version="6.6.23",
            vendor_commits=150,
            cve_matches=[
                {"cve_id": "CVE-2024-1234", "confidence": "high"},
                {"cve_id": "CVE-2024-5678", "confidence": "medium"},
            ],
        )
        s = analysis.summary()
        assert "toradex" in s
        assert "150 vendor commits" in s
        assert "2 CVE matches" in s
        assert "1 high confidence" in s

    def test_suppression_count(self):
        analysis = KernelForkAnalysis(
            vendor="test", fork_url="", fork_branch="",
            cve_matches=[
                {"confidence": "high"},
                {"confidence": "high"},
                {"confidence": "medium"},
            ],
        )
        assert analysis.suppression_count == 2
