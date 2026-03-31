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

from sciath_cli.output import OutputFormatter, _quality_grade


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
