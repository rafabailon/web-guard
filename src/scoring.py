"""Risk scoring and grading for audit results.

The model is intentionally simple and transparent. Every finding subtracts a
fixed number of points from a perfect score of one hundred. Informational
findings never reduce the score because they describe observations that do not
constitute a vulnerability on their own. The weights leave room for a few low
severity issues without hiding serious problems.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def calculate_score(findings: Iterable[Finding]) -> int:
    """Calculate a zero to one hundred score by summing severity weights."""

    deduction = sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings)
    return max(0, min(100, 100 - deduction))


def grade_for(score: int) -> str:
    """Map a numeric score to a letter grade."""

    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def risk_for(score: int, findings: Iterable[Finding]) -> str:
    """Return a short risk label that also accounts for critical findings."""

    findings = list(findings)
    if any(finding.severity is Severity.CRITICAL for finding in findings):
        return "critical"
    if score >= 90:
        return "low"
    if score >= 75:
        return "moderate"
    if score >= 50:
        return "elevated"
    if score >= 25:
        return "high"
    return "critical"


def score_summary(findings: Iterable[Finding]) -> tuple[int, str, str]:
    """Return score, grade and risk label in one call."""

    findings = list(findings)
    score = calculate_score(findings)
    return score, grade_for(score), risk_for(score, findings)
