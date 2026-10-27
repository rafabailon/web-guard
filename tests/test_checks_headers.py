"""Tests for HTTP security header checks."""

from __future__ import annotations

import pytest
from helpers import make_context
from web_guard.check_headers import HeaderCheck

SECURE_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    (
        "Content-Security-Policy",
        (
            "default-src 'self'; script-src 'self' https://cdn.example; object-src 'none'; "
            "frame-ancestors 'self'; base-uri 'self'"
        ),
    ),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
]


def run(headers, url="https://example.test/", html=None):
    return HeaderCheck().run(make_context(url=url, headers=headers, html=html))


def ids(findings):
    return {finding.id for finding in findings}


def test_missing_headers_are_reported():
    result = ids(run([]))
    assert {
        "headers.hsts.missing",
        "headers.csp.missing",
        "headers.xfo.missing",
        "headers.xcto.missing",
        "headers.referrer.missing",
        "headers.permissions.missing",
        "headers.coop.missing",
        "headers.corp.missing",
    } <= result


def test_fully_configured_site_has_no_header_findings():
    assert run(SECURE_HEADERS) == []


def test_hsts_is_not_required_on_plain_http():
    findings = run([], url="http://example.test/")
    assert "headers.hsts.missing" not in ids(findings)


@pytest.mark.parametrize(
    ("value", "expected_id"),
    [
        ("includeSubDomains", "headers.hsts.invalid"),
        ("max-age=0", "headers.hsts.zero"),
        ("max-age=3600", "headers.hsts.short"),
    ],
)
def test_hsts_values(value, expected_id):
    findings = run([("Strict-Transport-Security", value)])
    assert expected_id in ids(findings)


def test_hsts_short_lifetime_is_low_severity():
    findings = run([("Strict-Transport-Security", "max-age=3600")])
    finding = next(item for item in findings if item.id == "headers.hsts.short")
    assert finding.severity.value == "low"


def test_weak_csp_directives_are_detected():
    policy = "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'"
    findings = run([("Content-Security-Policy", policy)])
    result = ids(findings)
    assert {"headers.csp.unsafe_inline", "headers.csp.unsafe_eval", "headers.csp.wildcard"} <= result


def test_csp_missing_default_src_and_object_src():
    findings = run([("Content-Security-Policy", "script-src 'self'")])
    result = ids(findings)
    assert "headers.csp.no_default_src" in result
    assert "headers.csp.no_object_src" in result


def test_csp_report_only_does_not_replace_enforcing_policy():
    findings = run([("Content-Security-Policy-Report-Only", "default-src 'none'")])
    finding = next(item for item in findings if item.id == "headers.csp.missing")
    assert "Report-Only" in finding.evidence


def test_csp_frame_ancestors_replaces_x_frame_options():
    policy = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    findings = run([("Content-Security-Policy", policy)])
    assert "headers.xfo.missing" not in ids(findings)


def test_invalid_x_frame_options_value():
    findings = run([("X-Frame-Options", "ALLOWALL")])
    assert "headers.xfo.invalid" in ids(findings)


def test_allow_from_is_flagged_as_deprecated():
    findings = run([("X-Frame-Options", "ALLOW-FROM https://example.test")])
    assert "headers.xfo.allow_from" in ids(findings)


def test_invalid_content_type_options():
    findings = run([("X-Content-Type-Options", "sniff")])
    assert "headers.xcto.invalid" in ids(findings)


@pytest.mark.parametrize("value", ["unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"])
def test_weak_referrer_policy(value):
    findings = run([("Referrer-Policy", value)])
    assert "headers.referrer.weak" in ids(findings)


def test_missing_referrer_is_low_severity():
    findings = run([])
    finding = next(item for item in findings if item.id == "headers.referrer.missing")
    assert finding.severity.value == "low"


def test_header_names_are_case_insensitive():
    headers = [("strict-transport-security", "max-age=31536000")]
    findings = run(headers)
    assert "headers.hsts.missing" not in ids(findings)
