"""Tests for HTTPS and TLS checks."""

from __future__ import annotations

from helpers import make_context
from web_guard.check_transport import TransportCheck
from web_guard.models import TlsInfo


def tls(**overrides) -> TlsInfo:
    values = {
        "available": True,
        "verified": True,
        "version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "issuer": "CN=Test CA",
        "subject": "CN=example.test",
        "not_before": "2026-01-01",
        "not_after": "2027-01-01",
        "days_remaining": 90,
        "alt_names": ("example.test",),
    }
    values.update(overrides)
    return TlsInfo(**values)


def run(url="https://example.test/", final_url=None, tls_info=None, redirect_chain=None):
    return TransportCheck().run(
        make_context(url=url, final_url=final_url, tls=tls_info, redirect_chain=redirect_chain)
    )


def ids(findings):
    return {finding.id for finding in findings}


def test_strong_https_has_no_findings():
    assert run(tls_info=tls()) == []


def test_https_without_metadata_is_reported():
    assert "transport.tls.inspection_unavailable" in ids(run(tls_info=None))


def test_unavailable_tls_metadata_is_reported():
    assert "transport.tls.inspection_unavailable" in ids(run(tls_info=TlsInfo(available=False, error="refused")))


def test_untrusted_certificate():
    findings = run(tls_info=tls(verified=False, error="self signed certificate"))
    assert "transport.tls.untrusted" in ids(findings)
    assert "transport.tls.expired" not in ids(findings)


def test_expired_certificate():
    findings = run(tls_info=tls(days_remaining=-1, not_after="2025-01-01"))
    assert "transport.tls.expired" in ids(findings)


def test_certificate_expiring_within_seven_days_is_medium():
    findings = run(tls_info=tls(days_remaining=5))
    finding = next(item for item in findings if item.id == "transport.tls.expiring")
    assert finding.severity.value == "medium"


def test_certificate_expiring_within_thirty_days_is_low():
    findings = run(tls_info=tls(days_remaining=20))
    finding = next(item for item in findings if item.id == "transport.tls.expiring")
    assert finding.severity.value == "low"


def test_weak_protocol():
    findings = run(tls_info=tls(version="TLSv1.1"))
    assert "transport.tls.weak_protocol" in ids(findings)


def test_weak_cipher():
    findings = run(tls_info=tls(cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
    assert "transport.tls.weak_cipher" in ids(findings)


def test_http_only_target():
    findings = run(url="http://example.test/", tls_info=None)
    assert "transport.https.missing" in ids(findings)


def test_http_target_with_available_https():
    findings = run(url="http://example.test/", tls_info=tls())
    assert "transport.https.redirect_missing" in ids(findings)


def test_http_to_https_redirect_has_no_transport_findings():
    findings = run(
        url="http://example.test/",
        final_url="https://example.test/",
        tls_info=tls(),
        redirect_chain=["http://example.test/", "https://example.test/"],
    )
    assert findings == []


def test_https_to_http_downgrade():
    findings = run(
        url="https://example.test/",
        final_url="http://example.test/",
        tls_info=None,
        redirect_chain=["https://example.test/", "http://example.test/"],
    )
    assert "transport.https.downgrade" in ids(findings)
