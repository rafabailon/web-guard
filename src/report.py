"""Markdown and JSON report generation.

The Markdown report is the primary deliverable. It is written in continuous
prose with structured tables and fenced evidence, avoiding deeply nested lists so
that it stays readable in a terminal, a text editor and on GitHub. Remote values
are escaped before entering tables, and URLs displayed by the report have query
values redacted to avoid leaking tokens discovered during the scan.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .models import CheckStatus, Finding, ScanResult, Severity
from .scoring import SEVERITY_WEIGHTS
from .utils import clean_text, format_duration, redact_url

_SEVERITY_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def render_markdown(result: ScanResult) -> str:
    """Render a complete audit report as Markdown."""

    sections = [
        _header(result),
        _executive_summary(result),
        _risk_overview(result),
        _detection_section(result),
        _findings_summary(result),
        _detailed_findings(result),
        _checks_section(result),
        _methodology_section(),
        _limitations_section(),
        _scoring_section(),
        _footer(result),
    ]
    return "\n\n".join(section.strip() for section in sections if section.strip()) + "\n"


def render_json(result: ScanResult) -> str:
    """Render the machine readable form of a scan result."""

    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def _header(result: ScanResult) -> str:
    generated = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    started = result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Web Guard Security Audit",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Target | `{_cell(redact_url(result.target))}` |",
        f"| Final URL | `{_cell(redact_url(result.final_url))}` |",
        f"| Scan started | {started} |",
        f"| Scan duration | {format_duration(result.duration_seconds)} |",
        f"| Tool version | Web Guard {_cell(result.tool_version)} |",
        f"| Report generated | {generated} |",
        f"| Requests performed | {result.request_count} |",
        "",
        (
            "> **Authorization notice.** Run Web Guard only against systems you own or have explicit written "
            "permission to test. The scan sends ordinary GET, OPTIONS and TRACE requests to the target and a small "
            "fixed list of well-known paths. It does not exploit findings, brute force credentials or modify data."
        ),
    ]
    return "\n".join(lines)


def _executive_summary(result: ScanResult) -> str:
    counts = result.severity_counts
    total = len(result.findings)
    affecting = total - counts[Severity.INFO.value]
    highest = result.highest_severity
    lines = ["## Executive summary", ""]
    if total == 0:
        lines.append(
            f"Web Guard completed {len(result.outcomes)} checks against `{_cell(redact_url(result.final_url))}` "
            f"in {format_duration(result.duration_seconds)} and did not identify a security finding. The risk "
            f"score is {result.score}/100, grade {result.grade}, with a {result.risk} risk assessment. A clean "
            "automated result is encouraging but does not prove the absence of vulnerabilities, especially in "
            "authenticated areas, business logic and client-side code."
        )
    else:
        severity_text = (
            f"the highest severity is {_SEVERITY_LABELS[highest]}"
            if highest is not None
            else "no scored severity was recorded"
        )
        lines.append(
            f"Web Guard completed {len(result.outcomes)} checks against "
            f"`{_cell(redact_url(result.final_url))}` in {format_duration(result.duration_seconds)}. The scan "
            f"produced {total} finding(s), of which {affecting} affect the risk score. The score is "
            f"{result.score}/100 (grade {result.grade}, {result.risk} risk) and {severity_text}. "
            f"The counts are {counts[Severity.CRITICAL.value]} critical, {counts[Severity.HIGH.value]} high, "
            f"{counts[Severity.MEDIUM.value]} medium, {counts[Severity.LOW.value]} low and "
            f"{counts[Severity.INFO.value]} informational."
        )
        impactful = [finding for finding in result.sorted_findings() if finding.severity is not Severity.INFO]
        if impactful:
            top = "; ".join(
                f"{_SEVERITY_LABELS[finding.severity].lower()}: {finding.title}" for finding in impactful[:3]
            )
            lines.extend(["", f"The most urgent issues are {top}."])
        else:
            lines.extend(["", "The remaining observations are informational and do not reduce the score."])
        lines.extend(
            [
                "",
                (
                    "Prioritise critical and high findings first, then address medium issues that affect "
                    "authentication, session handling or data exposure. Every finding below includes evidence and a "
                    "concrete remediation."
                ),
            ]
        )
    return "\n".join(lines)


def _risk_overview(result: ScanResult) -> str:
    counts = result.severity_counts
    highest = _SEVERITY_LABELS[result.highest_severity] if result.highest_severity else "None"
    lines = [
        "## Risk overview",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Risk score | {result.score}/100 |",
        f"| Grade | {result.grade} |",
        f"| Risk level | {result.risk.capitalize()} |",
        f"| Highest severity | {highest} |",
        f"| Total findings | {len(result.findings)} |",
        f"| Requests performed | {result.request_count} |",
        "",
        "| Severity | Findings | Score weight each |",
        "| --- | ---: | ---: |",
    ]
    for severity in Severity.ordered():
        lines.append(
            f"| {_SEVERITY_LABELS[severity]} | {counts[severity.value]} | {SEVERITY_WEIGHTS[severity]} |"
        )
    return "\n".join(lines)


def _detection_section(result: ScanResult) -> str:
    detection = result.detection
    technologies = ", ".join(detection.technologies) if detection.technologies else "Not identified"
    redirects = " -> ".join(redact_url(item) for item in detection.redirect_chain)
    rows = [
        ("Requested URL", redact_url(detection.requested_url)),
        ("Final URL", redact_url(detection.final_url)),
        ("HTTP status", str(detection.status_code)),
        ("Page title", clean_text(detection.title, 200) or "Not available"),
        ("Resolved IP", detection.ip_address or "Not resolved"),
        ("Server", clean_text(detection.server, 200) or "Not disclosed"),
        ("X-Powered-By", clean_text(detection.powered_by, 200) or "Not disclosed"),
        ("Content type", detection.content_type or "Not declared"),
        ("Body size inspected", f"{detection.content_length} bytes"),
        ("HTTP version", detection.http_version or "Unknown"),
        ("Response time", f"{detection.response_time_ms:.1f} ms"),
        ("Redirect chain", redirects),
        ("Technologies", technologies),
    ]
    lines = [
        "## Detected environment",
        "",
        (
            "The fingerprint below is based on response headers, cookies, page markup and the TLS handshake. "
            "Technologies are inferred from weak signals and should be confirmed by the owner."
        ),
        "",
        "| Property | Value |",
        "| --- | --- |",
    ]
    for label, value in rows:
        lines.append(f"| {label} | {_cell(value)} |")

    tls = detection.tls
    if tls is not None:
        lines.extend(
            [
                "",
                "### TLS details",
                "",
                "| Property | Value |",
                "| --- | --- |",
                f"| Available | {'Yes' if tls.available else 'No'} |",
                f"| Certificate trusted | {'Yes' if tls.verified else 'No'} |",
                f"| Protocol | {_cell(tls.version or 'Unknown')} |",
                f"| Cipher | {_cell(tls.cipher or 'Unknown')} |",
                f"| Subject | {_cell(tls.subject or 'Unknown')} |",
                f"| Issuer | {_cell(tls.issuer or 'Unknown')} |",
                f"| Valid from | {_cell(tls.not_before or 'Unknown')} |",
                f"| Valid until | {_cell(tls.not_after or 'Unknown')} |",
                f"| Days remaining | {tls.days_remaining if tls.days_remaining is not None else 'Unknown'} |",
                f"| SAN entries | {_cell(', '.join(tls.alt_names[:10]) or 'None reported')} |",
                f"| Error | {_cell(tls.error or 'None')} |",
            ]
        )
    return "\n".join(lines)


def _findings_summary(result: ScanResult) -> str:
    lines = ["## Findings summary", ""]
    if not result.findings:
        lines.append("No findings were recorded by the selected checks.")
        return "\n".join(lines)
    lines.extend(
        [
            "| Identifier | Severity | Title |",
            "| --- | --- | --- |",
        ]
    )
    for finding in result.sorted_findings():
        lines.append(
            f"| `{_cell(finding.id)}` | {_SEVERITY_LABELS[finding.severity]} | {_cell(finding.title)} |"
        )
    return "\n".join(lines)


def _detailed_findings(result: ScanResult) -> str:
    lines = ["## Detailed findings", ""]
    if not result.findings:
        lines.append(
            "There are no detailed findings to report. The checks that passed are listed in the next section."
        )
        return "\n".join(lines)

    for severity in Severity.ordered():
        group = [finding for finding in result.sorted_findings() if finding.severity is severity]
        if not group:
            continue
        lines.extend([f"### {_SEVERITY_LABELS[severity]} severity", ""])
        for index, finding in enumerate(group, start=1):
            lines.extend(_render_finding(finding, index))
            lines.append("")
    return "\n".join(lines).strip()


def _render_finding(finding: Finding, index: int) -> list[str]:
    meta = [
        f"**Identifier:** `{_cell(finding.id)}`  ",
        f"**Severity:** {_SEVERITY_LABELS[finding.severity]}  ",
        f"**Check:** `{_cell(finding.check)}`  ",
        f"**Category:** {_cell(finding.category)}  ",
    ]
    if finding.cwe:
        meta.append(f"**CWE:** {_cell(finding.cwe)}  ")
    lines = [
        f"#### {index}. {_cell(finding.title)}",
        "",
        *meta,
        "",
        finding.description.strip(),
        "",
        "**Evidence**",
        "",
        _code_block(finding.evidence, "text"),
        "",
        "**Remediation**",
        "",
        finding.remediation.strip(),
    ]
    if finding.references:
        lines.extend(["", "**References**", ""])
        for reference in finding.references:
            lines.append(f"- {_cell(reference)}")
    lines.append("")
    lines.append("---")
    return lines


def _checks_section(result: ScanResult) -> str:
    lines = [
        "## Checks executed",
        "",
        "| Check | Identifier | Status | Findings | Duration | Detail |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    status_labels = {
        CheckStatus.PASSED: "Passed",
        CheckStatus.ISSUES: "Issues",
        CheckStatus.SKIPPED: "Skipped",
        CheckStatus.ERROR: "Error",
    }
    for outcome in result.outcomes:
        lines.append(
            f"| {_cell(outcome.name)} | `{_cell(outcome.check_id)}` | {status_labels[outcome.status]} | "
            f"{len(outcome.findings)} | {outcome.duration_ms:.1f} ms | {_cell(outcome.detail or '-')} |"
        )
    return "\n".join(lines)


def _methodology_section() -> str:
    return (
        "## Methodology\n\n"
        "Web Guard retrieved the target document over HTTP or HTTPS, followed a bounded number of redirects and "
        "parsed the delivered markup. It then ran the selected checks against that response and a small number of "
        "additional requests. Those requests are an OPTIONS and a TRACE to test method exposure, a request with a "
        "synthetic Origin header for CORS, a random nonexistent path to establish a soft-404 baseline, a fixed list "
        "of well-known sensitive paths, and the security.txt location. Every request uses a configurable delay, a "
        "timeout, a body size limit and a descriptive user agent. No authentication is attempted, no form is "
        "submitted, no payload is injected and no data is modified. Findings are evaluated from response metadata, "
        "headers, cookies, negotiated TLS parameters and static markup. The report records only cookie names, never "
        "cookie values, and redacts discovered secret patterns."
    )


def _limitations_section() -> str:
    return (
        "## Limitations\n\n"
        "This is an automated external audit of a single entry point. It cannot assess vulnerabilities that require "
        "authentication, multi-step business logic, race conditions, file upload abuse, payment flows or access to "
        "internal infrastructure. It does not crawl the site, enumerate virtual hosts, brute force paths or "
        "credentials, fuzz parameters, execute JavaScript, inspect single page application routes or test the "
        "security of third-party dependencies. TLS inspection reports the negotiated connection but does not "
        "enumerate every supported protocol and cipher suite. WAF behaviour, geographic differences, CDN caching "
        "and load balancing can make individual responses unrepresentative. Automated findings, particularly the "
        "CSRF token heuristic and technology fingerprint, can be false positives and should be confirmed manually. "
        "Use this report as a prioritised starting point for a broader assessment, not as a certification of "
        "security."
    )


def _scoring_section() -> str:
    lines = [
        "## Scoring model",
        "",
        (
            "The score starts at 100 and subtracts a fixed weight for every finding. Informational findings carry no "
            "weight. The score is clamped to the range 0 to 100. Repeated findings of the same class are aggregated "
            "by the checks where practical, which keeps a large number of similar symptoms from dominating the "
            "result."
        ),
        "",
        "| Severity | Weight |",
        "| --- | ---: |",
    ]
    for severity in Severity.ordered():
        lines.append(f"| {_SEVERITY_LABELS[severity]} | {SEVERITY_WEIGHTS[severity]} |")
    lines.extend(
        [
            "",
            (
                "Grades are A for 90 and above, B for 80, C for 70, D for 60, E for 40 and F below 40. A critical "
                "finding always raises the risk label to critical regardless of the numeric score. The model is "
                "intentionally transparent and conservative; it is not a CVSS replacement."
            ),
        ]
    )
    return "\n".join(lines)


def _footer(result: ScanResult) -> str:
    return (
        "---\n\n"
        f"Generated by Web Guard {_cell(result.tool_version)}. The tool is defensive and read-only. "
        "Verify every finding in the context of the application before making changes, and retest after remediation."
    )


def _cell(value: Any, limit: int = 300) -> str:
    """Escape a value for a Markdown table cell."""

    text = clean_text(str(value), limit)
    return text.replace("|", "\\|")


def _code_block(value: str, language: str = "") -> str:
    """Create a fenced block whose fence cannot be terminated by the content."""

    text = str(value).replace("\r\n", "\n").strip()
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{language}\n{text}\n{fence}"
