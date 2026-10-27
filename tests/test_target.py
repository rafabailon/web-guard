"""Tests for target parsing and normalisation."""

from __future__ import annotations

import pytest
from web_guard.errors import TargetError
from web_guard.target import normalize_target, target_from_input


def test_missing_scheme_defaults_to_https():
    target = target_from_input("example.com")
    assert target.url == "https://example.com/"
    assert target.scheme == "https"
    assert target.implicit_scheme is True


def test_scheme_and_host_are_lowercased_and_fragment_removed():
    assert normalize_target("HTTP://Example.COM:80/a#frag") == "http://example.com/a"


def test_default_https_port_is_removed():
    assert normalize_target("https://example.com:443/") == "https://example.com/"


def test_non_default_port_and_query_are_preserved():
    assert normalize_target("https://example.com:8443/path?x=1&y=2") == (
        "https://example.com:8443/path?x=1&y=2"
    )


def test_empty_path_becomes_root():
    assert normalize_target("https://example.com") == "https://example.com/"


def test_trailing_dot_is_removed():
    assert normalize_target("https://example.com./") == "https://example.com/"


def test_ipv6_literal_is_bracketed():
    target = target_from_input("https://[2001:db8::1]:8443/x")
    assert target.host == "2001:db8::1"
    assert target.url == "https://[2001:db8::1]:8443/x"


def test_ipv4_is_preserved():
    assert normalize_target("http://127.0.0.1:8080/") == "http://127.0.0.1:8080/"


def test_idn_host_is_converted_to_punycode():
    assert normalize_target("https://bücher.example/") == "https://xn--bcher-kva.example/"


def test_target_origin_and_explicit_port():
    target = target_from_input("https://example.com:8443/app")
    assert target.origin == "https://example.com:8443"
    assert target.explicit_port is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "ftp://example.com/",
        "file:///etc/passwd",
        "https://user:pass@example.com/",
        "https://example.com:99999/",
        "http://",
        "https:///path",
        "https://exa mple.com/",
        "https://example..com/",
        "https://-bad.example/",
        "https://bad-.example/",
        "https://example.com/\n",
    ],
)
def test_invalid_targets_are_rejected(value):
    with pytest.raises(TargetError):
        target_from_input(value)


def test_non_string_target_is_rejected():
    with pytest.raises(TargetError):
        target_from_input(None)  # type: ignore[arg-type]


def test_credentials_are_not_silently_removed():
    with pytest.raises(TargetError, match="Credentials"):
        target_from_input("https://token@example.com/")
