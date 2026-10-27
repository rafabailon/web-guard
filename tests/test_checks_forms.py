"""Tests for mixed content, forms, links and embedded secrets."""

from __future__ import annotations

from helpers import make_context
from web_guard.check_content import ContentCheck


def run(html: str, url: str = "https://example.test/"):
    return ContentCheck().run(make_context(url=url, html=html))


def ids(findings):
    return {finding.id for finding in findings}


def test_active_and_passive_mixed_content_are_separated():
    html = """
    <html><body>
      <script src="http://cdn.example/app.js"></script>
      <img src="http://images.example/a.png">
    </body></html>
    """
    findings = run(html)
    assert "content.mixed.active" in ids(findings)
    assert "content.mixed.passive" in ids(findings)


def test_mixed_content_is_ignored_on_http_pages():
    html = '<script src="http://cdn.example/app.js"></script>'
    assert "content.mixed.active" not in ids(run(html, url="http://example.test/"))


def test_namespace_urls_are_not_mixed_content():
    html = '<html xmlns="http://www.w3.org/1999/xhtml"><body></body></html>'
    assert "content.mixed.active" not in ids(run(html))


def test_password_form_posting_to_http_is_high():
    html = """
    <form method="post" action="http://login.example.test/auth">
      <input type="password" name="password">
      <input type="hidden" name="csrf_token" value="x">
    </form>
    """
    findings = run(html)
    finding = next(item for item in findings if item.id == "content.forms.insecure_action")
    assert finding.severity.value == "high"


def test_password_form_on_http_page_is_high():
    html = '<form method="post" action="/login"><input type="password" name="p"></form>'
    findings = run(html, url="http://example.test/")
    finding = next(item for item in findings if item.id == "content.forms.password_http")
    assert finding.severity.value == "high"


def test_get_password_form_is_medium():
    html = '<form method="get" action="/login"><input type="password" name="p"></form>'
    findings = run(html)
    finding = next(item for item in findings if item.id == "content.forms.password_get")
    assert finding.severity.value == "medium"


def test_post_password_form_without_csrf_token_is_low():
    html = '<form method="post" action="/login"><input type="password" name="p"></form>'
    findings = run(html)
    finding = next(item for item in findings if item.id == "content.forms.csrf_token_missing")
    assert finding.severity.value == "low"


def test_post_password_form_with_csrf_token_is_clean():
    html = """
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="x">
      <input type="password" name="p">
    </form>
    """
    assert "content.forms.csrf_token_missing" not in ids(run(html))


def test_javascript_form_action_is_reported():
    html = '<form method="post" action="javascript:alert(1)"><input type="password" name="p"></form>'
    assert "content.forms.javascript_action" in ids(run(html))


def test_target_blank_without_noopener_is_reported():
    html = '<a href="/next" target="_blank">next</a>'
    assert "content.links.noopener" in ids(run(html))


def test_target_blank_with_noopener_is_clean():
    html = '<a href="/next" target="_blank" rel="noopener noreferrer">next</a>'
    assert "content.links.noopener" not in ids(run(html))


def test_private_key_is_critical_and_redacted():
    html = "<html><body>-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----</body></html>"
    findings = run(html)
    finding = next(item for item in findings if item.id == "content.secrets.private_key")
    assert finding.severity.value == "critical"
    assert "MIIE" not in finding.evidence


def test_aws_key_is_high_and_redacted():
    html = "<html><body>AKIAIOSFODNN7EXAMPLE</body></html>"
    findings = run(html)
    finding = next(item for item in findings if item.id == "content.secrets.aws_key")
    assert finding.severity.value == "high"
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence


def test_google_api_key_is_medium():
    key = "AIza" + "A" * 35
    findings = run(f"<html><body>{key}</body></html>")
    assert "content.secrets.google_api_key" in ids(findings)


def test_clean_document_has_no_content_findings():
    html = """
    <html><head><title>Clean</title></head><body>
      <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="x">
        <input type="password" name="p">
      </form>
      <a href="/next" target="_blank" rel="noopener">next</a>
    </body></html>
    """
    assert run(html) == []


def test_non_html_context_is_ignored():
    context = make_context(url="https://example.test/", body="plain", html=None)
    assert ContentCheck().run(context) == []
