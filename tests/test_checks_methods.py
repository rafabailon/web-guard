"""Tests for HTTP method exposure checks."""

from __future__ import annotations

import pytest
from helpers import FakeClient, make_context, make_response
from web_guard.check_methods import MethodCheck
from web_guard.errors import CheckSkipped, RequestError


def build_client(allow: str | None = None, trace_status: int = 405, echo: bool = False):
    def handler(url, method, headers):
        if method == "OPTIONS":
            if allow is None:
                return RequestError("OPTIONS blocked")
            return make_response(url, headers=[("Allow", allow)])
        if method == "TRACE":
            if trace_status == 200:
                marker = (headers or {}).get("X-WebGuard-Trace", "")
                return make_response(
                    url,
                    status=200,
                    body=marker if echo else "trace disabled",
                    headers=[("Content-Type", "message/http")],
                )
            return make_response(url, status=trace_status)
        return make_response(url, status=405)

    return FakeClient(handler)


def run(allow=None, trace_status=405, echo=False):
    return MethodCheck().run(make_context(client=build_client(allow, trace_status, echo)))


def ids(findings):
    return {finding.id for finding in findings}


def test_trace_enabled_and_echoing_is_high():
    findings = run(allow="GET, OPTIONS, TRACE", trace_status=200, echo=True)
    finding = next(item for item in findings if item.id == "methods.trace_enabled")
    assert finding.severity.value == "high"


def test_trace_without_echo_is_not_reported():
    findings = run(allow="GET, OPTIONS", trace_status=200, echo=False)
    assert "methods.trace_enabled" not in ids(findings)


def test_unsafe_methods_are_informational():
    findings = run(allow="GET, PUT, DELETE, PATCH")
    finding = next(item for item in findings if item.id == "methods.unsafe_advertised")
    assert finding.severity.value == "info"


def test_failed_requests_skip_check():
    client = FakeClient(lambda *_args: RequestError("blocked"))
    with pytest.raises(CheckSkipped):
        MethodCheck().run(make_context(client=client))


def test_one_failed_probe_does_not_skip_check():
    findings = run(allow=None, trace_status=200, echo=True)
    assert "methods.trace_enabled" in ids(findings)


def test_clean_methods_return_no_findings():
    assert run(allow="GET, HEAD, OPTIONS", trace_status=405) == []
