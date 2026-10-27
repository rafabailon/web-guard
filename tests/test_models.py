"""Tests for the serialisable data model."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from web_guard.models import (
    CheckOutcome,
    CheckStatus,
    Detection,
    Finding,
    ScanResult,
    Severity,
    TlsInfo,
    flatten_findings,
)


def sample_finding(severity: Severity = Severity.HIGH, identifier: str = "headers.test") -> Finding:
    return Finding(
        id=identifier,
        check="headers",
        title="A finding",
        severity=severity,
        category="Headers",
        description="Description",
        evidence="Evidence",
        remediation="Fix it",
        references=("https://example.test/ref",),
        cwe="CWE-693",
    )


def test_severity_ordering_and_parsing():
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.parse(" info ") is Severity.INFO
    assert Severity.ordered() == (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_invalid_severity_raises():
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.parse("urgent")


def test_finding_serialisation():
    data = sample_finding().to_dict()
    assert data["id"] == "headers.test"
    assert data["severity"] == "high"
    assert data["references"] == ["https://example.test/ref"]
    assert data["cwe"] == "CWE-693"


def test_outcome_serialisation():
    finding = sample_finding()
    outcome = CheckOutcome(
        check_id="headers",
        name="Headers",
        status=CheckStatus.ISSUES,
        findings=[finding],
        duration_ms=1.23456,
    )
    data = outcome.to_dict()
    assert data["status"] == "issues"
    assert data["duration_ms"] == 1.235
    assert len(data["findings"]) == 1


def test_tls_info_summary_and_serialisation():
    tls = TlsInfo(
        available=True,
        verified=True,
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        issuer="CN=Test CA",
        days_remaining=90,
    )
    assert "TLSv1.3" in tls.summary
    assert "90 days remaining" in tls.summary
    assert tls.to_dict()["issuer"] == "CN=Test CA"
    assert TlsInfo(available=False).summary == "Not available"


def build_result(findings: list[Finding], outcomes: list[CheckOutcome] | None = None) -> ScanResult:
    detection = Detection(
        requested_url="https://example.test/",
        final_url="https://example.test/",
        status_code=200,
        title="Example",
    )
    return ScanResult(
        target="https://example.test/",
        final_url="https://example.test/",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        duration_seconds=0.5,
        detection=detection,
        outcomes=outcomes or [],
        findings=findings,
        score=80,
        grade="B",
        risk="moderate",
        tool_version="1.0.0",
    )


def test_scan_result_counts_sorting_and_threshold():
    low = sample_finding(Severity.LOW, "a.low")
    high = sample_finding(Severity.HIGH, "b.high")
    info = sample_finding(Severity.INFO, "c.info")
    result = build_result([low, info, high])
    assert result.severity_counts == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 1}
    assert result.highest_severity is Severity.HIGH
    assert [item.id for item in result.sorted_findings()] == ["b.high", "a.low", "c.info"]
    assert result.has_at_least(Severity.MEDIUM) is True
    assert result.has_at_least(Severity.CRITICAL) is False


def test_scan_result_without_findings():
    result = build_result([])
    assert result.highest_severity is None
    assert result.severity_counts["critical"] == 0
    assert result.has_at_least(Severity.INFO) is False


def test_naive_started_at_gets_utc_timezone():
    result = build_result([])
    assert result.started_at.tzinfo is UTC


def test_scan_result_serialisation_and_outcome_filtering():
    high = sample_finding()
    outcome = CheckOutcome(
        check_id="headers",
        name="Headers",
        status=CheckStatus.ISSUES,
        findings=[high],
    )
    result = build_result([high], [outcome])
    result.settings = {"timeout": 1.0}
    data = result.to_dict()
    assert data["findings"][0]["id"] == "headers.test"
    assert data["settings"]["timeout"] == 1.0
    assert data["severity_counts"]["high"] == 1
    assert result.outcomes_by_status(CheckStatus.ISSUES) == [outcome]
    assert flatten_findings([outcome]) == [high]
