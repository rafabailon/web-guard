"""Tests for cookie attribute checks."""

from __future__ import annotations

import pytest
from helpers import make_context
from web_guard.check_cookies import CookieCheck, parse_set_cookie


def run(cookies, url="https://example.test/"):
    headers = [("Set-Cookie", value) for value in cookies]
    return CookieCheck().run(make_context(url=url, headers=headers))


def ids(findings):
    return {finding.id for finding in findings}


def test_parse_set_cookie_does_not_keep_value():
    cookie = parse_set_cookie("sessionid=topsecret; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert cookie is not None
    assert cookie.name == "sessionid"
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "lax"
    assert "topsecret" not in repr(cookie)


def test_parse_invalid_set_cookie_returns_none():
    assert parse_set_cookie("not-a-cookie") is None
    assert parse_set_cookie("=value") is None


def test_session_cookie_missing_all_attributes():
    findings = run(["sessionid=secretvalue; Path=/"])
    assert ids(findings) == {
        "cookies.secure.missing",
        "cookies.httponly.missing",
        "cookies.samesite.missing",
    }
    assert all("secretvalue" not in finding.evidence for finding in findings)


def test_fully_protected_cookie_has_no_findings():
    assert run(["sessionid=secret; Secure; HttpOnly; SameSite=Lax"]) == []


def test_csrf_cookie_is_not_required_to_be_httponly():
    findings = run(["csrftoken=token; Secure; SameSite=Lax"])
    assert "cookies.httponly.missing" not in ids(findings)


def test_samesite_none_without_secure():
    findings = run(["prefs=value; SameSite=None"])
    assert "cookies.samesite.none_without_secure" in ids(findings)
    assert "cookies.secure.missing" in ids(findings)


def test_host_prefix_requires_secure_root_path_and_no_domain():
    findings = run(["__Host-session=abc; Path=/app; Domain=example.test; SameSite=Strict"])
    assert "cookies.prefix.host" in ids(findings)


def test_valid_host_prefix_is_accepted():
    assert run(["__Host-session=abc; Secure; Path=/; HttpOnly; SameSite=Strict"]) == []


def test_secure_prefix_requires_secure_attribute():
    findings = run(["__Secure-session=abc; HttpOnly; SameSite=Strict"])
    assert "cookies.prefix.secure" in ids(findings)


def test_generic_cookie_uses_lower_severities():
    findings = run(["language=en; Secure; HttpOnly; SameSite=Lax"])
    assert findings == []


def test_multiple_cookies_are_aggregated():
    findings = run(
        [
            "sessionid=abc; Path=/",
            "csrftoken=def; Path=/",
        ]
    )
    secure = next(item for item in findings if item.id == "cookies.secure.missing")
    assert "sessionid" in secure.evidence
    assert "csrftoken" in secure.evidence
    assert secure.severity.value == "high"
    assert len([item for item in findings if item.id == "cookies.secure.missing"]) == 1


def test_no_cookies_produces_no_findings():
    assert run([]) == []


@pytest.mark.parametrize("raw", ["a=b", "a=b; Secure", "a=b; HttpOnly", "a=b; SameSite=Strict"])
def test_single_attribute_cookies(raw):
    findings = run([raw])
    assert findings
