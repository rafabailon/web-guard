"""Tests for the risk scoring model."""

from __future__ import annotations

import pytest
from web_guard.models import Finding, Severity
from web_guard.scoring import (
    SEVERITY_WEIGHTS,
    calculate_score,
    grade_for,
    risk_for,
    score_summary,
)


def finding(severity: Severity, identifier: str = "test.finding") -> Finding:
    return Finding(
        id=identifier,
        check="test",
        title="Test",
        severity=severity,
        category="Test",
        description="Test",
        evidence="Test",
        remediation="Test",
    )


def test_empty_scan_scores_one_hundred():
    assert calculate_score([]) == 100
    assert score_summary([]) == (100, "A", "low")


def test_informational_findings_do_not_reduce_score():
    assert calculate_score([finding(Severity.INFO)]) == 100


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, 60),
        (Severity.HIGH, 80),
        (Severity.MEDIUM, 92),
        (Severity.LOW, 97),
        (Severity.INFO, 100),
    ],
)
def test_single_finding_weight(severity, expected):
    assert calculate_score([finding(severity)]) == expected
    assert SEVERITY_WEIGHTS[severity] == 100 - expected


def test_score_is_clamped_to_zero():
    assert calculate_score([finding(Severity.CRITICAL, f"x.{index}") for index in range(5)]) == 0


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"), (69, "D"), (60, "D"), (59, "E"), (40, "E"), (39, "F"), (0, "F")],
)
def test_grade_boundaries(score, grade):
    assert grade_for(score) == grade


def test_critical_finding_forces_critical_risk_label():
    findings = [finding(Severity.CRITICAL)]
    score = calculate_score(findings)
    assert risk_for(score, findings) == "critical"


@pytest.mark.parametrize(
    ("score", "label"),
    [(100, "low"), (90, "low"), (89, "moderate"), (75, "moderate"), (74, "elevated"), (50, "elevated"), (49, "high"), (25, "high"), (24, "critical")],
)
def test_risk_labels(score, label):
    assert risk_for(score, []) == label
