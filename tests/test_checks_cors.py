"""Tests for the CORS policy check."""

from __future__ import annotations

import pytest
from helpers import FakeClient, make_context, make_response
from web_guard.check_cors import CorsCheck
from web_guard.errors import CheckSkipped, RequestError


def client_for(headers, status=200):
    def handler(url, method, request_headers):
        return make_response(url, status=status, headers=headers)

    return FakeClient(handler)


def run(headers, status=200):
    client = client_for(headers, status)
    return CorsCheck().run(make_context(client=client))


def ids(findings):
    return {finding.id for finding in findings}


def test_no_cors_headers_means_no_finding():
    assert run([]) == []


def test_reflected_origin_without_credentials_is_medium():
    findings = run([("Access-Control-Allow-Origin", "https://webguard.invalid")])
    finding = next(item for item in findings if item.id == "cors.reflected_origin")
    assert finding.severity.value == "medium"


def test_reflected_origin_with_credentials_is_high():
    findings = run(
        [
            ("Access-Control-Allow-Origin", "https://webguard.invalid"),
            ("Access-Control-Allow-Credentials", "true"),
        ]
    )
    finding = next(item for item in findings if item.id == "cors.reflected_credentials")
    assert finding.severity.value == "high"


def test_wildcard_origin_is_low():
    findings = run([("Access-Control-Allow-Origin", "*")])
    assert "cors.wildcard" in ids(findings)


def test_wildcard_with_credentials_is_medium():
    findings = run(
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ]
    )
    assert "cors.wildcard_credentials" in ids(findings)


def test_null_origin_is_reported():
    findings = run([("Access-Control-Allow-Origin", "null")])
    assert "cors.null_origin" in ids(findings)


def test_multiple_origins_are_reported():
    findings = run([("Access-Control-Allow-Origin", "https://a.test, https://b.test")])
    assert "cors.invalid_origin_list" in ids(findings)


def test_unknown_fixed_origin_is_not_flagged():
    assert run([("Access-Control-Allow-Origin", "https://trusted.example")]) == []


def test_origin_header_is_sent():
    client = client_for([("Access-Control-Allow-Origin", "*")])
    CorsCheck().run(make_context(client=client))
    _url, method, headers = client.calls[0]
    assert method == "GET"
    assert headers["Origin"] == "https://webguard.invalid"


def test_request_failure_skips_check():
    client = FakeClient(lambda *_args: RequestError("network down"))
    with pytest.raises(CheckSkipped, match="CORS probe"):
        CorsCheck().run(make_context(client=client))
