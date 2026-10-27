"""Tests for shared utility helpers."""

from __future__ import annotations

from web_guard.utils import (
    clean_text,
    content_type_of,
    format_duration,
    host_from_url,
    is_html_content_type,
    is_http_resource,
    is_http_url,
    is_text_content_type,
    origin_of,
    redact_url,
    resolve_url,
    unique,
    url_without_fragment,
)


def test_clean_text_collapses_whitespace_and_controls():
    assert clean_text("a\n\tb\x00c") == "a b c"
    assert clean_text("abcdef", limit=4) == "abc…"


def test_url_helpers():
    assert resolve_url("https://example.test/a/", "b") == "https://example.test/a/b"
    assert origin_of("https://example.test/a?b=1") == "https://example.test"
    assert origin_of("relative") == ""
    assert host_from_url("https://example.test:8443/") == "example.test"
    assert url_without_fragment("https://example.test/a#frag") == "https://example.test/a"
    assert is_http_url("https://example.test/") is True
    assert is_http_url("mailto:user@example.test") is False
    assert is_http_resource("http://example.test/a") is True
    assert is_http_resource("https://example.test/a") is False


def test_content_type_helpers():
    assert content_type_of("Text/HTML; charset=UTF-8") == "text/html"
    assert is_html_content_type("text/html; charset=utf-8") is True
    assert is_html_content_type("application/xhtml+xml") is True
    assert is_html_content_type("application/json") is False
    assert is_text_content_type("text/plain") is True
    assert is_text_content_type("application/problem+json") is True
    assert is_text_content_type("image/png") is False


def test_redact_url_removes_fragment_and_query_values():
    assert redact_url("https://example.test/a?token=abc&q=1#frag") == (
        "https://example.test/a?token=REDACTED&q=REDACTED"
    )
    assert redact_url("https://example.test/a#frag") == "https://example.test/a"
    assert redact_url("/relative?x=1") == "/relative?x=REDACTED"


def test_unique_preserves_first_seen_order():
    assert unique(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_duration_formatting():
    assert format_duration(0.123) == "123 ms"
    assert format_duration(1.234) == "1.23 s"
