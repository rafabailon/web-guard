"""Tests for Markdown and JSON report rendering."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from web_guard.models import (
    CheckOutcome,
    CheckStatus,
    Detection,
    Finding,
    ScanResult,
    Severity,
    TlsInfo,
)
from web_guard.report import render_json, render_markdown


def finding(
    identifier: str = "headers.csp.missing",
    severity: Severity = Severity.MEDIUM,
    check: str = "headers",
    title: str = "Content-Security-Policy is missing",
    evidence: str = "Content-Security-Policy is absent.",
) -> Finding:
    return Finding(
        id=identifier,
        check=check,
        title=title,
        severity=severity,
        category="Content security",
        description="The response does not define a policy.",
        evidence=evidence,
        remediation="Deploy a restrictive policy.",
        references=("https://example.test/reference",),
        cwe="CWE-693",
    )


def result(findings=None, outcomes=None, final_url="https://example.test/app?token=secret") -> ScanResult:
    findings = list(findings or [])
    outcomes = list(outcomes or [])
    return ScanResult(
        target="https://example.test/",
        final_url=final_url,
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        duration_seconds=1.25,
        detection=Detection(
            requested_url="https://example.test/",
            final_url=final_url,
            status_code=200,
            title="Example",
            ip_address="192.0.2.10",
            server="nginx/1.24.0",
            content_type="text/html",
            content_length=1200,
            http_version="HTTP/2",
            response_time_ms=12.5,
            redirect_chain=("https://example.test/", final_url),
            technologies=("Nginx",),
            tls=TlsInfo(
                available=True,
                verified=True,
                version="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                issuer="Example CA",
                subject="example.test",
                not_before="2026-01-01",
                not_after="2026-12-31",
                days_remaining=300,
                alt_names=("example.test",),
            ),
        ),
        outcomes=outcomes,
        findings=findings,
        score=92,
        grade="A",
        risk="low",
        tool_version="1.0.0",
        checks_requested=("headers",),
        request_count=12,
        settings={"delay": 0.0},
    )


def test_markdown_contains_every_major_section():
    report = render_markdown(result(findings=[finding()]))
    for heading in (
        "# Web Guard Security Audit",
        "## Executive summary",
        "## Risk overview",
        "## Detected environment",
        "### TLS details",
        "## Findings summary",
        "## Detailed findings",
        "## Checks executed",
        "## Methodology",
        "## Limitations",
        "## Scoring model",
    ):
        assert heading in report
    assert "Authorization notice" in report
    assert "TLSv1.3" in report
    assert "CWE-693" in report
    assert "https://example.test/reference" in report


def test_markdown_redacts_query_values_in_displayed_urls():
    report = render_markdown(result(final_url="https://example.test/app?token=topsecret"))
    assert "topsecret" not in report
    assert "https://example.test/app" in report


def test_markdown_reports_a_clean_result_without_findings():
    report = render_markdown(result())
    assert "did not identify a security finding" in report
    assert "No findings were recorded" in report
    assert "There are no detailed findings" in report


def test_markdown_escapes_table_cells_and_fences():
    nasty = finding(
        identifier="custom.check",
        title="Title with | a pipe",
        evidence="before ``` inside after",
    )
    report = render_markdown(result(findings=[nasty]))
    assert "Title with \\| a pipe" in report
    assert "````text" in report


def test_markdown_lists_skipped_and_failed_checks():
    outcomes = [
        CheckOutcome(
            check_id="headers",
            name="HTTP security headers",
            status=CheckStatus.SKIPPED,
            detail="Permission denied.",
            duration_ms=1.25,
        ),
        CheckOutcome(
            check_id="cors",
            name="CORS policy",
            status=CheckStatus.ERROR,
            detail="RequestError: boom",
            duration_ms=2.5,
        ),
    ]
    report = render_markdown(result(outcomes=outcomes))
    assert "| HTTP security headers | `headers` | Skipped |" in report
    assert "| CORS policy | `cors` | Error |" in report
    assert "Permission denied." in report


def test_json_report_is_valid_and_matches_the_model():
    findings = [finding(), finding(identifier="cookies.secure.missing", severity=Severity.HIGH)]
    report = render_json(result(findings=findings))
    payload = json.loads(report)
    assert payload["tool"] == "web-guard"
    assert payload["tool_version"] == "1.0.0"
    assert payload["score"] == 92
    assert payload["grade"] == "A"
    assert payload["severity_counts"]["high"] == 1
    assert payload["severity_counts"]["medium"] == 1
    assert payload["detection"]["technologies"] == ["Nginx"]
    assert payload["detection"]["tls"]["version"] == "TLSv1.3"
    assert len(payload["findings"]) == 2
    assert payload["settings"] == {"delay": 0.0}
    assert report.endswith("\n")


def test_markdown_sorts_findings_by_severity():
    findings = [
        finding(identifier="low.one", severity=Severity.LOW),
        finding(identifier="critical.one", severity=Severity.CRITICAL, title="Critical issue"),
    ]
    report = render_markdown(result(findings=findings))
    assert report.index("critical.one") < report.index("low.one")
