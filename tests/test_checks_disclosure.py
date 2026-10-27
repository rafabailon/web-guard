"""Tests for information disclosure checks."""

from __future__ import annotations

from helpers import make_context, make_response
from web_guard.check_disclosure import DisclosureCheck


def run(headers=None, html=None, status=200, not_found=None, final="https://example.test/"):
    return DisclosureCheck().run(
        make_context(
            final_url=final,
            status=status,
            headers=headers or [],
            html=html,
            not_found=not_found,
        )
    )


def ids(findings):
    return {finding.id for finding in findings}


def test_version_banners_are_reported():
    findings = run(
        headers=[
            ("Server", "nginx/1.24.0"),
            ("X-Powered-By", "PHP/8.2.1"),
            ("X-AspNet-Version", "4.0.30319"),
            ("X-AspNetMvc-Version", "5.2"),
            ("X-Generator", "Drupal 10"),
        ]
    )
    result = ids(findings)
    assert "disclosure.server_version" in result
    assert "disclosure.powered_by" in result
    assert "disclosure.x_aspnet_version" in result
    assert "disclosure.x_aspnetmvc_version" in result
    assert "disclosure.x_generator" in result


def test_server_without_version_is_not_reported():
    assert "disclosure.server_version" not in ids(run(headers=[("Server", "nginx")]))


def test_debug_tokens_are_reported():
    findings = run(headers=[("X-Debug-Token", "abc123"), ("X-Debug-Token-Link", "/profiler/abc123")])
    result = ids(findings)
    assert "disclosure.x_debug_token" in result
    assert "disclosure.x_debug_token_link" in result


def test_generator_meta_with_version_is_informational():
    findings = run(html='<meta name="generator" content="WordPress 6.4.2">')
    finding = next(item for item in findings if item.id == "disclosure.generator_meta")
    assert finding.severity.value == "info"


def test_generator_meta_without_version_is_ignored():
    assert "disclosure.generator_meta" not in ids(run(html='<meta name="generator" content="Hugo">'))


def test_directory_listing_is_detected():
    findings = run(html="<html><head><title>Index of /files</title></head><body></body></html>")
    assert "disclosure.directory_listing" in ids(findings)


def test_python_traceback_on_missing_path_is_medium():
    not_found = make_response(
        "https://example.test/missing",
        status=500,
        body="Traceback (most recent call last):\n  File app.py",
    )
    findings = run(not_found=not_found)
    finding = next(item for item in findings if item.id == "disclosure.verbose_error")
    assert finding.severity.value == "medium"
    assert "traceback" in finding.evidence.lower()


def test_php_warning_is_low():
    not_found = make_response(
        "https://example.test/missing",
        status=500,
        body="Warning: include(config.php): failed to open stream on line 42",
    )
    findings = run(not_found=not_found)
    finding = next(item for item in findings if item.id == "disclosure.verbose_error")
    assert finding.severity.value == "low"


def test_clean_not_found_page_is_not_reported():
    not_found = make_response("https://example.test/missing", status=404, body="Not found")
    assert "disclosure.verbose_error" not in ids(run(not_found=not_found))


def test_no_not_found_response_is_safe():
    assert "disclosure.verbose_error" not in ids(run())
