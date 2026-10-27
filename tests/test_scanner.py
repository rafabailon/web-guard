"""Integration tests for scan orchestration."""

from __future__ import annotations

import socket

import pytest
from web_guard.check_base import Check
from web_guard.checks import select_checks
from web_guard.config import Settings
from web_guard.errors import ConfigError, ScanError, TargetError
from web_guard.models import CheckStatus
from web_guard.scanner import scan
from web_guard.version import __version__

HTML = """
<!doctype html>
<html>
<head>
  <title>Example App</title>
  <meta name="generator" content="WordPress 6.4">
</head>
<body>
  <form method="post" action="/login">
    <input type="password" name="password">
  </form>
  <script src="http://cdn.example/app.js"></script>
  <a href="/next" target="_blank">next</a>
</body>
</html>
"""


def insecure_routes(server_url: str):
    def trace(handler, method):
        marker = handler.headers.get("X-WebGuard-Trace", "")
        return 200, marker, [("Content-Type", "message/http")]

    return {
        "/": (
            200,
            HTML,
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Server", "nginx/1.24.0"),
                ("Set-Cookie", "sessionid=topsecret; Path=/"),
                ("Access-Control-Allow-Origin", "https://webguard.invalid"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ),
        "OPTIONS /": (200, b"", [("Allow", "GET, OPTIONS, TRACE, PUT")]),
        "TRACE /": trace,
        "/.env": (200, "SECRET_KEY=topsecret\n", [("Content-Type", "text/plain")]),
        "/.well-known/security.txt": (
            200,
            "Contact: mailto:security@example.test\n",
            [("Content-Type", "text/plain")],
        ),
    }


def scan_settings(**overrides) -> Settings:
    values = {"delay": 0.0, "timeout": 1.5, "probe_tls": False}
    values.update(overrides)
    return Settings(**values)


def test_full_scan_against_local_server(serve):
    server = serve(insecure_routes(""))
    result = scan(f"{server.url}/", settings=scan_settings())
    assert result.target == f"{server.url}/"
    assert result.final_url == f"{server.url}/"
    assert result.tool_version == __version__
    assert len(result.outcomes) == 9
    assert len(result.checks_requested) == 9
    assert result.request_count > 8
    assert result.detection.title == "Example App"
    assert "WordPress" in result.detection.technologies
    assert "Nginx" in result.detection.technologies
    assert result.detection.server == "nginx/1.24.0"
    assert result.detection.ip_address == "127.0.0.1"
    ids = {finding.id for finding in result.findings}
    assert {
        "transport.https.missing",
        "headers.csp.missing",
        "cookies.secure.missing",
        "cors.reflected_credentials",
        "methods.trace_enabled",
        "disclosure.server_version",
        "content.forms.password_http",
        "files.dotenv",
    } <= ids
    assert "wellknown.security_txt.missing" not in ids
    assert result.score < 50
    assert result.grade in {"E", "F"}
    assert result.risk in {"high", "critical"}
    assert result.severity_counts["critical"] == 1
    assert "topsecret" not in str([finding.to_dict() for finding in result.findings])


def test_scan_can_restrict_checks(serve):
    server = serve(insecure_routes(""))
    checks = select_checks(["headers"])
    result = scan(f"{server.url}/", settings=scan_settings(), checks=checks)
    assert result.checks_requested == ("headers",)
    assert len(result.outcomes) == 1
    assert result.outcomes[0].check_id == "headers"
    assert all(finding.check == "headers" for finding in result.findings)


def test_check_failure_is_isolated(serve):
    server = serve({"/": (200, b"<html><title>ok</title></html>", [])})

    class BrokenCheck(Check):
        id = "broken"
        name = "Broken check"
        description = "Always fails."
        order = 1

        def run(self, context):
            raise RuntimeError("boom")

    result = scan(f"{server.url}/", settings=scan_settings(), checks=[BrokenCheck()])
    assert len(result.outcomes) == 1
    assert result.outcomes[0].status is CheckStatus.ERROR
    assert "boom" in result.outcomes[0].detail
    assert result.findings == []
    assert result.score == 100


def test_skipped_check_is_recorded(serve):
    from web_guard.errors import CheckSkipped

    server = serve({"/": (200, b"<html></html>", [])})

    class SkippedCheck(Check):
        id = "skipped"
        name = "Skipped check"
        description = "Skipped."
        order = 1

        def run(self, context):
            raise CheckSkipped("not applicable")

    result = scan(f"{server.url}/", settings=scan_settings(), checks=[SkippedCheck()])
    assert result.outcomes[0].status is CheckStatus.SKIPPED
    assert result.outcomes[0].detail == "not applicable"


def test_empty_check_list_is_rejected(serve):
    server = serve({"/": (200, b"", [])})
    with pytest.raises(ConfigError, match="At least one check"):
        scan(f"{server.url}/", settings=scan_settings(), checks=[])


def test_scan_failure_raises_scan_error():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(ScanError, match="Could not retrieve"):
        scan(f"http://127.0.0.1:{port}/", settings=scan_settings())


def test_invalid_target_raises_target_error():
    with pytest.raises(TargetError):
        scan("ftp://example.test/", settings=scan_settings())


def test_redirect_is_reflected_in_detection(serve):
    server = serve(
        {
            "/start": (302, b"", [("Location", "/final")]),
            "/final": (200, b"<html><title>Final</title></html>", []),
        }
    )
    result = scan(
        f"{server.url}/start",
        settings=scan_settings(),
        checks=select_checks(["headers"]),
    )
    assert result.final_url == f"{server.url}/final"
    assert result.detection.redirect_chain == (f"{server.url}/start", f"{server.url}/final")
    assert result.detection.title == "Final"


def test_scheme_discovery_falls_back_to_http(serve):
    server = serve({"/": (200, b"<html><title>Fallback</title></html>", [])})
    target = f"127.0.0.1:{server.httpd.server_port}/"
    result = scan(target, settings=scan_settings(), checks=select_checks(["headers"]))
    assert result.target.startswith("http://")
    assert result.final_url == f"{server.url}/"
    assert result.detection.title == "Fallback"


def test_progress_callback_receives_every_check(serve):
    server = serve({"/": (200, b"<html></html>", [])})
    seen: list[str] = []
    scan(
        f"{server.url}/",
        settings=scan_settings(),
        checks=select_checks(["headers", "cookies"]),
        progress=lambda check_id, name: seen.append(check_id),
    )
    assert seen == ["headers", "cookies"]
