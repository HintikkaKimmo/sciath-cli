"""
Safety-net tests for OutputFormatter and _quality_grade().

These tests lock down current behavior before refactoring.
They protect against silent breakage when deduplicating _quality_grade()
and consolidating output logic.
"""
import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from sciath_cli.output import OutputFormatter, _quality_grade, render_cra_readiness


class TestQualityGradeBoundaries:
    """Verify every grade boundary for _quality_grade()."""

    @pytest.mark.parametrize(
        "score, expected",
        [
            (0.0, "F"),
            (0.59, "F"),
            (0.6, "D"),
            (0.69, "D"),
            (0.7, "C"),
            (0.79, "C"),
            (0.8, "B"),
            (0.89, "B"),
            (0.9, "A"),
            (1.0, "A"),
        ],
    )
    def test_quality_grade_boundaries(self, score: float, expected: str) -> None:
        assert _quality_grade(score) == expected


class TestRenderScanJsonFormat:
    """Verify JSON output is valid and contains expected fields."""

    def test_render_scan_json_format(self) -> None:
        formatter = OutputFormatter(format="json")
        data = {
            "id": "scan-uuid-1234-5678",
            "status": "triage",
            "version_label": "v1.0",
            "total_components": 42,
            "total_vulnerabilities": 10,
            "suppressed_count": 7,
            "remaining_count": 3,
            "analysed_at": "2026-03-31T12:00:00Z",
            "sbom_quality_score": 0.85,
        }

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data)

        output = captured.getvalue()
        parsed = json.loads(output)

        assert parsed["scan_id"] == "scan-uuid-1234-5678"
        assert parsed["status"] == "triage"
        assert parsed["version"] == "v1.0"
        assert parsed["total_components"] == 42
        assert parsed["total_vulnerabilities"] == 10
        assert parsed["suppressed_count"] == 7
        assert parsed["remaining_count"] == 3
        assert parsed["sbom_quality_score"] == 0.85

    def test_render_scan_json_with_assessments(self) -> None:
        formatter = OutputFormatter(format="json")
        data = {
            "id": "scan-uuid-abcd",
            "status": "triage",
            "total_components": 10,
            "total_vulnerabilities": 2,
            "suppressed_count": 1,
        }
        assessments = [
            {
                "vulnerability": {
                    "vuln_id": "CVE-2024-0001",
                    "cvss_score": 9.8,
                    "epss_score": 0.5,
                    "is_kev": True,
                    "matched_sources": ["nvd"],
                    "confidence_tier": "high",
                    "component": {"name": "openssl"},
                },
                "status": "affected",
                "filter_layer": "none",
                "applied_filter_layers": [],
                "justification_text": "",
                "confidence": "high",
                "contextual_cvss": 9.8,
            },
        ]

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data, assessments=assessments)

        parsed = json.loads(captured.getvalue())
        assert len(parsed["assessments"]) == 1
        assert parsed["assessments"][0]["cve_id"] == "CVE-2024-0001"
        assert parsed["assessments"][0]["is_kev"] is True


class TestRenderScanQuietFormat:
    """Quiet mode: no stdout output, just exit code computation."""

    def test_render_scan_quiet_format(self) -> None:
        formatter = OutputFormatter(format="quiet")
        data = {
            "id": "scan-uuid-quiet",
            "status": "triage",
            "total_components": 5,
            "total_vulnerabilities": 3,
            "suppressed_count": 1,
        }

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data)

        # Quiet format should not write to stdout
        assert captured.getvalue() == ""


class TestExitCodes:
    """Verify exit code logic based on scan data and severity thresholds."""

    def test_exit_code_no_threshold(self) -> None:
        """Without severity_threshold or fail_on_kev, exit code stays 0."""
        formatter = OutputFormatter(format="quiet")
        data = {
            "total_vulnerabilities": 10,
            "suppressed_count": 3,
            "remaining_count": 7,
        }
        formatter.render_scan(data)
        assert formatter.exit_code == 0

    def test_exit_code_severity_threshold_triggered(self) -> None:
        """With critical threshold and a critical CVE, exit code is 1."""
        formatter = OutputFormatter(format="quiet", severity_threshold="critical")
        data = {
            "total_vulnerabilities": 1,
            "suppressed_count": 0,
            "remaining_count": 1,
        }
        assessments = [
            {
                "vulnerability": {"cvss_score": 9.8},
                "status": "affected",
            },
        ]
        formatter.render_scan(data, assessments=assessments)
        assert formatter.exit_code == 1

    def test_exit_code_severity_threshold_not_triggered(self) -> None:
        """With critical threshold but only medium CVEs, exit code stays 0."""
        formatter = OutputFormatter(format="quiet", severity_threshold="critical")
        data = {
            "total_vulnerabilities": 1,
            "suppressed_count": 0,
            "remaining_count": 1,
        }
        assessments = [
            {
                "vulnerability": {"cvss_score": 5.0},
                "status": "affected",
            },
        ]
        formatter.render_scan(data, assessments=assessments)
        assert formatter.exit_code == 0

    def test_exit_code_severity_threshold_not_affected_ignored(self) -> None:
        """Critical CVE marked not_affected should not trigger exit 1."""
        formatter = OutputFormatter(format="quiet", severity_threshold="critical")
        data = {
            "total_vulnerabilities": 1,
            "suppressed_count": 1,
            "remaining_count": 0,
        }
        assessments = [
            {
                "vulnerability": {"cvss_score": 9.8},
                "status": "not_affected",
            },
        ]
        formatter.render_scan(data, assessments=assessments)
        assert formatter.exit_code == 0

    def test_exit_code_kev_triggered(self) -> None:
        """With fail_on_kev and an open KEV finding, exit code is 1."""
        formatter = OutputFormatter(format="quiet", fail_on_kev=True)
        data = {
            "total_vulnerabilities": 1,
            "suppressed_count": 0,
            "remaining_count": 1,
        }
        assessments = [
            {
                "vulnerability": {"is_kev": True, "cvss_score": 7.0},
                "status": "affected",
            },
        ]
        formatter.render_scan(data, assessments=assessments)
        assert formatter.exit_code == 1

    def test_exit_code_kev_not_affected_ignored(self) -> None:
        """KEV finding marked not_affected should not trigger exit 1."""
        formatter = OutputFormatter(format="quiet", fail_on_kev=True)
        data = {
            "total_vulnerabilities": 1,
            "suppressed_count": 1,
            "remaining_count": 0,
        }
        assessments = [
            {
                "vulnerability": {"is_kev": True, "cvss_score": 7.0},
                "status": "not_affected",
            },
        ]
        formatter.render_scan(data, assessments=assessments)
        assert formatter.exit_code == 0

    def test_exit_code_no_assessments(self) -> None:
        """With threshold but no assessments, exit code stays 0."""
        formatter = OutputFormatter(format="quiet", severity_threshold="low")
        data = {
            "total_vulnerabilities": 0,
            "suppressed_count": 0,
            "remaining_count": 0,
        }
        formatter.render_scan(data, assessments=None)
        assert formatter.exit_code == 0


# Sample funnel data used across waterfall tests
_SAMPLE_FUNNEL = {
    "raw": 847,
    "layers": [
        {"name": "build_time", "remaining": 612, "suppressed": 235, "label": "packages not on device"},
        {"name": "kconfig", "remaining": 341, "suppressed": 271, "label": "subsystems disabled"},
        {"name": "dtb", "remaining": 267, "suppressed": 74, "label": "peripherals not present"},
        {"name": "packageconfig", "remaining": 189, "suppressed": 78, "label": "features not enabled"},
        {"name": "busybox", "remaining": 156, "suppressed": 33, "label": "applets not compiled"},
        {"name": "patch", "remaining": 98, "suppressed": 58, "label": "already backported"},
        {"name": "custom", "remaining": 89, "suppressed": 9, "label": "org-specific exclusions"},
        {"name": "deployment", "remaining": 89, "suppressed": 0, "label": "no matches"},
    ],
    "action_required": 89,
}


class TestWaterfallRenderer:
    """Verify the suppression funnel waterfall renders correctly."""

    def test_waterfall_renders_in_table_format(self, capsys) -> None:
        """Table format includes the waterfall when funnel data is present."""
        formatter = OutputFormatter(format="table")
        data = {
            "id": "scan-uuid-1234",
            "status": "triage",
            "version_label": "v2.3.1",
            "total_components": 200,
            "total_vulnerabilities": 847,
            "suppressed_count": 758,
            "remaining_count": 89,
            "suppression_funnel": _SAMPLE_FUNNEL,
        }
        formatter.render_scan(data)

        captured = capsys.readouterr().out
        assert "847" in captured
        assert "Kconfig suppression" in captured
        assert "341" in captured
        assert "ACTION REQUIRED" in captured
        assert "89" in captured

    def test_waterfall_shows_skipped_layers(self, capsys) -> None:
        """Layers without artifacts show 'skipped' label."""
        funnel = {
            "raw": 10,
            "layers": [
                {"name": "build_time", "remaining": 10, "suppressed": 0, "label": "no matches"},
                {"name": "kconfig", "remaining": 10, "suppressed": 0, "label": "skipped — no kconfig uploaded"},
                {"name": "dtb", "remaining": 10, "suppressed": 0, "label": "skipped — no DTB uploaded"},
                {"name": "packageconfig", "remaining": 10, "suppressed": 0, "label": "skipped — no PACKAGECONFIG uploaded"},
                {"name": "busybox", "remaining": 10, "suppressed": 0, "label": "skipped — no busybox config uploaded"},
                {"name": "patch", "remaining": 10, "suppressed": 0, "label": "skipped — no patch evidence uploaded"},
                {"name": "custom", "remaining": 10, "suppressed": 0, "label": "skipped — no custom filter uploaded"},
                {"name": "deployment", "remaining": 10, "suppressed": 0, "label": "skipped — no deployment policy uploaded"},
            ],
            "action_required": 10,
        }
        formatter = OutputFormatter(format="table")
        data = {
            "id": "scan-uuid-skip",
            "status": "triage",
            "total_components": 5,
            "total_vulnerabilities": 10,
            "suppressed_count": 0,
            "remaining_count": 10,
            "suppression_funnel": funnel,
        }
        formatter.render_scan(data)

        captured = capsys.readouterr().out
        assert "skipped" in captured
        assert "no kconfig uploaded" in captured

    def test_waterfall_not_rendered_without_funnel(self, capsys) -> None:
        """When suppression_funnel is absent, no waterfall is shown."""
        formatter = OutputFormatter(format="table")
        data = {
            "id": "scan-uuid-nofunnel",
            "status": "triage",
            "total_components": 5,
            "total_vulnerabilities": 10,
            "suppressed_count": 3,
            "remaining_count": 7,
        }
        formatter.render_scan(data)

        captured = capsys.readouterr().out
        assert "Kconfig suppression" not in captured
        assert "ACTION REQUIRED" not in captured

    def test_waterfall_zero_action_required_shows_check(self, capsys) -> None:
        """When action_required is 0, show a green checkmark."""
        funnel = {
            "raw": 5,
            "layers": [
                {"name": "build_time", "remaining": 5, "suppressed": 0, "label": "no matches"},
                {"name": "kconfig", "remaining": 0, "suppressed": 5, "label": "subsystems disabled"},
                {"name": "dtb", "remaining": 0, "suppressed": 0, "label": "skipped — no DTB uploaded"},
                {"name": "packageconfig", "remaining": 0, "suppressed": 0, "label": "skipped — no PACKAGECONFIG uploaded"},
                {"name": "busybox", "remaining": 0, "suppressed": 0, "label": "skipped — no busybox config uploaded"},
                {"name": "patch", "remaining": 0, "suppressed": 0, "label": "skipped — no patch evidence uploaded"},
                {"name": "custom", "remaining": 0, "suppressed": 0, "label": "skipped — no custom filter uploaded"},
                {"name": "deployment", "remaining": 0, "suppressed": 0, "label": "skipped — no deployment policy uploaded"},
            ],
            "action_required": 0,
        }
        formatter = OutputFormatter(format="table")
        data = {
            "id": "scan-uuid-clear",
            "status": "triage",
            "total_components": 5,
            "total_vulnerabilities": 5,
            "suppressed_count": 5,
            "remaining_count": 0,
            "suppression_funnel": funnel,
        }
        formatter.render_scan(data)

        captured = capsys.readouterr().out
        assert "ACTION REQUIRED" in captured
        assert "0" in captured

    def test_json_includes_funnel(self) -> None:
        """JSON output includes suppression_funnel when present."""
        formatter = OutputFormatter(format="json")
        data = {
            "id": "scan-uuid-json",
            "status": "triage",
            "version_label": "v1.0",
            "total_components": 200,
            "total_vulnerabilities": 847,
            "suppressed_count": 758,
            "remaining_count": 89,
            "suppression_funnel": _SAMPLE_FUNNEL,
        }

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data)

        parsed = json.loads(captured.getvalue())
        assert "suppression_funnel" in parsed
        assert parsed["suppression_funnel"]["raw"] == 847
        assert len(parsed["suppression_funnel"]["layers"]) == 8
        assert parsed["suppression_funnel"]["action_required"] == 89

    def test_explain_shows_suppression_rationale(self, capsys) -> None:
        """Explain table prefers suppression_rationale over justification_text."""
        formatter = OutputFormatter(format="table", explain=True)
        data = {
            "id": "scan-uuid-explain",
            "status": "triage",
            "total_components": 5,
            "total_vulnerabilities": 1,
            "suppressed_count": 1,
            "remaining_count": 0,
        }
        assessments = [
            {
                "vulnerability": {"vuln_id": "CVE-2024-1234"},
                "status": "not_affected",
                "filter_layer": "kconfig",
                "applied_filter_layers": ["kconfig"],
                "justification_text": "old generic text",
                "suppression_rationale": "CONFIG_BT=n — subsystem not compiled (.config)",
                "confidence": "high",
            },
        ]
        formatter.render_scan(data, assessments=assessments)

        captured = capsys.readouterr().out
        assert "CONFIG_BT=n" in captured
        assert ".config" in captured
        # Should show rationale, not the old justification_text
        assert "old generic text" not in captured

    def test_json_includes_suppression_rationale(self) -> None:
        """JSON output includes suppression_rationale for each assessment."""
        formatter = OutputFormatter(format="json")
        data = {
            "id": "scan-uuid-rationale",
            "status": "triage",
            "version_label": "v1.0",
            "total_components": 5,
            "total_vulnerabilities": 1,
            "suppressed_count": 1,
            "remaining_count": 0,
        }
        assessments = [
            {
                "vulnerability": {
                    "vuln_id": "CVE-2024-1234",
                    "cvss_score": 7.5,
                    "epss_score": 0.3,
                    "is_kev": False,
                    "matched_sources": ["nvd"],
                    "confidence_tier": "high",
                    "component": {"name": "linux"},
                },
                "status": "not_affected",
                "filter_layer": "kconfig",
                "applied_filter_layers": ["kconfig"],
                "justification_text": "",
                "suppression_rationale": "CONFIG_BT=n — subsystem not compiled (.config)",
                "confidence": "high",
                "contextual_cvss": None,
            },
        ]

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data, assessments=assessments)

        parsed = json.loads(captured.getvalue())
        assert parsed["assessments"][0]["suppression_rationale"] == "CONFIG_BT=n — subsystem not compiled (.config)"

    def test_json_omits_funnel_when_absent(self) -> None:
        """JSON output does not include suppression_funnel when not present."""
        formatter = OutputFormatter(format="json")
        data = {
            "id": "scan-uuid-nofunnel",
            "status": "triage",
            "version_label": "v1.0",
            "total_components": 5,
            "total_vulnerabilities": 10,
            "suppressed_count": 3,
            "remaining_count": 7,
        }

        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            formatter.render_scan(data)

        parsed = json.loads(captured.getvalue())
        assert "suppression_funnel" not in parsed


_SAMPLE_CRA_READINESS = {
    "verdict": "not_ready",
    "percentage": 71.4,
    "checklist": [
        {"requirement": "Software Bill of Materials", "article": "Art. 13(1)", "status": "passed", "detail": "SBOM present, quality 85%", "is_blocker": False},
        {"requirement": "No unresolved Critical CVEs", "article": "Art. 13(8)", "status": "failed", "detail": "2 Critical CVEs unresolved", "is_blocker": True},
        {"requirement": "No open CISA KEV entries", "article": "Art. 11", "status": "passed", "detail": "0 CISA KEV entries open", "is_blocker": False},
        {"requirement": "VEX justifications documented", "article": "Art. 14", "status": "passed", "detail": "341/341 suppressions with rationale", "is_blocker": False},
        {"requirement": "Known vulnerability disclosure", "article": "Art. 13(6)", "status": "passed", "detail": "847/847 CVEs triaged (100%)", "is_blocker": False},
        {"requirement": "Unique product identification", "article": "Art. 13(5)", "status": "passed", "detail": "Project: Gateway, Version: v2.3.1", "is_blocker": False},
        {"requirement": "Article 13 Technical File", "article": "Art. 13", "status": "warning", "detail": "Not yet generated", "is_blocker": False},
        {"requirement": "Security update mechanism", "article": "Art. 11", "status": "out_of_scope", "detail": "OTA is outside Sciath's domain", "is_blocker": False},
        {"requirement": "Contact info for vulnerability reporting", "article": "Art. 13(5b)", "status": "out_of_scope", "detail": "Organisational requirement", "is_blocker": False},
    ],
    "blockers": ["2 Critical CVEs unresolved (Art. 13.8)"],
    "warnings": [],
}


class TestCRAReadinessRenderer:
    """Verify CRA readiness rendering."""

    def test_renders_verdict_table(self, capsys) -> None:
        render_cra_readiness(_SAMPLE_CRA_READINESS, output_format="table")
        captured = capsys.readouterr().out
        assert "NOT READY" in captured
        assert "71" in captured
        assert "Art. 13(1)" in captured
        assert "Critical CVEs" in captured

    def test_renders_blockers(self, capsys) -> None:
        render_cra_readiness(_SAMPLE_CRA_READINESS, output_format="table")
        captured = capsys.readouterr().out
        assert "Blockers" in captured
        assert "Critical CVEs unresolved" in captured

    def test_shippable_verdict(self, capsys) -> None:
        data = {
            "verdict": "shippable",
            "percentage": 100.0,
            "checklist": [
                {"requirement": "SBOM", "article": "Art. 13(1)", "status": "passed", "detail": "OK", "is_blocker": False},
            ],
            "blockers": [],
            "warnings": [],
        }
        render_cra_readiness(data, output_format="table")
        captured = capsys.readouterr().out
        assert "SHIPPABLE" in captured
        assert "100" in captured

    def test_json_output(self) -> None:
        captured = StringIO()
        with patch.object(sys, "stdout", captured):
            render_cra_readiness(_SAMPLE_CRA_READINESS, output_format="json")
        parsed = json.loads(captured.getvalue())
        assert parsed["verdict"] == "not_ready"
        assert len(parsed["checklist"]) == 9
        assert parsed["percentage"] == 71.4

    def test_quiet_no_output(self, capsys) -> None:
        render_cra_readiness(_SAMPLE_CRA_READINESS, output_format="quiet")
        captured = capsys.readouterr().out
        assert captured == ""
