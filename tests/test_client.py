"""Tests for the HTTP client, including redirects, limits and timeouts."""

from __future__ import annotations

import time

import pytest
from helpers import make_response
from web_guard.config import Settings
from web_guard.errors import RequestError
from web_guard.http_client import HttpClient, is_weak_cipher, tls_probe_target


def client(**overrides) -> HttpClient:
    values = {"delay": 0.0, "timeout": 1.0, "probe_tls": False}
    values.update(overrides)
    return HttpClient(Settings(**values))


def test_basic_request_returns_headers_body_and_cookies(serve):
    server = serve(
        {
            "/": (
                200,
                b"hello",
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("X-Test", "yes"),
                    ("Set-Cookie", "a=b; Secure"),
                    ("Set-Cookie", "c=d; HttpOnly"),
                ],
            )
        }
    )
    response = client().request(f"{server.url}/")
    assert response.status == 200
    assert response.text == "hello"
    assert response.header("x-test") == "yes"
    assert response.header_values("set-cookie") == ["a=b; Secure", "c=d; HttpOnly"]
    assert response.cookies == ["a=b; Secure", "c=d; HttpOnly"]
    assert response.content_type == "text/plain"
    assert response.truncated is False
    assert response.redirect_chain == (f"{server.url}/",)


def test_redirect_chain_is_recorded(serve):
    server = serve(
        {
            "/start": (302, b"", [("Location", "/middle")]),
            "/middle": (301, b"", [("Location", "/final")]),
            "/final": (200, b"done", [("Content-Type", "text/plain")]),
        }
    )
    http = client()
    response = http.request(f"{server.url}/start")
    assert response.status == 200
    assert response.url == f"{server.url}/final"
    assert response.redirect_chain == (
        f"{server.url}/start",
        f"{server.url}/middle",
        f"{server.url}/final",
    )
    assert http.request_count == 3


def test_redirect_limit_is_enforced(serve):
    server = serve(
        {
            "/a": (302, b"", [("Location", "/b")]),
            "/b": (302, b"", [("Location", "/c")]),
            "/c": (200, b"", []),
        }
    )
    with pytest.raises(RequestError, match="Too many redirects"):
        client(max_redirects=1).request(f"{server.url}/a")


def test_redirect_loop_is_detected(serve):
    server = serve({"/loop": (302, b"", [("Location", "/loop")])})
    with pytest.raises(RequestError, match="Redirect loop"):
        client().request(f"{server.url}/loop")


def test_redirect_to_unsupported_scheme_is_rejected(serve):
    server = serve({"/start": (302, b"", [("Location", "ftp://example.test/file")])})
    with pytest.raises(RequestError, match="absolute http"):
        client().request(f"{server.url}/start")


def test_body_is_truncated(serve):
    server = serve({"/big": (200, b"x" * 5000, [("Content-Type", "text/plain")])})
    response = client(max_body_bytes=1024).request(f"{server.url}/big")
    assert len(response.body) == 1024
    assert response.truncated is True


def test_custom_headers_are_sent(serve):
    def echo(handler, method):
        return 200, handler.headers.get("X-Custom", ""), [("Content-Type", "text/plain")]

    server = serve({"/echo": echo})
    response = client().request(f"{server.url}/echo", headers={"X-Custom": "value"})
    assert response.text == "value"


def test_head_request_has_no_body(serve):
    server = serve({"/page": (200, b"body", [("Content-Type", "text/plain")])})
    response = client().request(f"{server.url}/page", method="HEAD")
    assert response.status == 200
    assert response.body == b""


def test_post_body_is_sent(serve):
    def echo(handler, method):
        length = int(handler.headers.get("Content-Length", "0"))
        return 200, handler.rfile.read(length), [("Content-Type", "text/plain")]

    server = serve({"POST /echo": echo})
    response = client().request(f"{server.url}/echo", method="POST", body=b"payload")
    assert response.text == "payload"


def test_non_success_status_is_returned(serve):
    server = serve({"/missing": (404, b"not found", [("Content-Type", "text/plain")])})
    response = client().request(f"{server.url}/missing")
    assert response.status == 404


def test_timeout_is_wrapped(serve):
    def slow(handler, method):
        time.sleep(0.3)
        return 200, b"late", [("Content-Type", "text/plain")]

    server = serve({"/slow": slow})
    with pytest.raises(RequestError, match="timed out"):
        client(timeout=0.1).request(f"{server.url}/slow")


def test_invalid_request_urls_are_rejected():
    with pytest.raises(RequestError):
        client().request("ftp://example.test/file")
    with pytest.raises(RequestError):
        client().request("https://user:pass@example.test/")


def test_transport_error_is_wrapped():
    with pytest.raises(RequestError, match="Request failed"):
        client(timeout=0.2).request("http://127.0.0.1:1/")


def test_elapsed_time_and_http_version_are_recorded(serve):
    server = serve({"/": (200, b"", [("Content-Type", "text/plain")])})
    response = client().request(f"{server.url}/")
    assert response.elapsed_ms >= 0
    assert response.http_version.startswith("HTTP/")


@pytest.mark.parametrize(
    ("cipher", "weak"),
    [
        ("TLS_AES_256_GCM_SHA384", False),
        ("TLS_CHACHA20_POLY1305_SHA256", False),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", True),
        ("TLS_RSA_WITH_RC4_128_SHA", True),
        ("TLS_RSA_WITH_NULL_SHA", True),
    ],
)
def test_weak_cipher_detection(cipher, weak):
    assert is_weak_cipher(cipher) is weak


def test_tls_probe_target_rules():
    assert tls_probe_target("http://example.test/") == ("example.test", 443)
    assert tls_probe_target("http://example.test:80/") == ("example.test", 443)
    assert tls_probe_target("http://example.test:8080/") is None
    assert tls_probe_target("https://example.test/") is None


def test_response_builder_helper_is_stable():
    response = make_response("https://example.test/", status=201, body="text")
    assert response.status == 201
    assert response.text == "text"
    assert response.content_type == "text/html"
