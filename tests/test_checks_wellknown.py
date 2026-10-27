"""Tests for security.txt discovery."""

from __future__ import annotations

import pytest
from helpers import FakeClient, make_context, make_response
from web_guard.check_wellknown import WellKnownCheck
from web_guard.errors import CheckSkipped, RequestError

BASE = "https://example.test/"


def run(response):
    client = FakeClient(lambda url, method, headers: response)
    return WellKnownCheck().run(make_context(url=BASE, client=client))


def test_valid_security_txt_has_no_finding():
    response = make_response(
        f"{BASE}.well-known/security.txt",
        headers=[("Content-Type", "text/plain")],
        body="Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n",
    )
    assert run(response) == []


def test_security_txt_without_contact_is_informational():
    response = make_response(f"{BASE}.well-known/security.txt", body="Expires: 2027-01-01T00:00:00Z")
    findings = run(response)
    assert findings[0].id == "wellknown.security_txt.invalid"
    assert findings[0].severity.value == "info"


def test_missing_security_txt_is_informational():
    response = make_response(f"{BASE}.well-known/security.txt", status=404, body="Not found")
    findings = run(response)
    assert findings[0].id == "wellknown.security_txt.missing"
    assert findings[0].severity.value == "info"


def test_protected_security_txt_skips_check():
    response = make_response(f"{BASE}.well-known/security.txt", status=403)
    with pytest.raises(CheckSkipped):
        run(response)


def test_request_error_skips_check():
    client = FakeClient(lambda *_args: RequestError("offline"))
    with pytest.raises(CheckSkipped):
        WellKnownCheck().run(make_context(url=BASE, client=client))


def test_security_txt_url_is_root_relative():
    client = FakeClient(
        lambda url, method, headers: make_response(f"{BASE}.well-known/security.txt", body="Contact: https://x.test")
    )
    context = make_context(url="https://example.test/app/deep", client=client)
    WellKnownCheck().run(context)
    assert client.calls[0][0] == f"{BASE}.well-known/security.txt"
