"""Shared fixtures for the Web Guard test suite.

Tests use real loopback HTTP servers rather than mocking the socket layer, which
exercises redirects, headers, truncation and TLS handshakes end to end. Unit
level checks additionally use small context builders and a stub client so that
each branch can be tested without network noise.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urlsplit

from web_guard.errors import RequestError
from web_guard.models import TlsInfo

ResponseSpec = tuple[int, bytes | str, list[tuple[str, str]]]
Route = ResponseSpec | Callable[["RouteHandler", str], ResponseSpec]


class QuietHTTPServer(ThreadingHTTPServer):
    """A threaded server that never prints client disconnect tracebacks."""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


class RouteHandler(BaseHTTPRequestHandler):
    """Configurable handler used by the tests.

    Routes are keyed by ``"METHOD /path"``. A plain path key is treated as a GET
    route. Unknown methods return 405 and unknown paths return 404, which keeps
    the helper predictable for scanners that probe several endpoints.
    """

    routes: ClassVar[dict[str, Route]] = {}
    base_headers: ClassVar[list[tuple[str, str]]] = []
    server_version = "WebGuardTest"
    sys_version = ""

    def version_string(self) -> str:
        return "WebGuardTest"

    def send_response(self, code: int, message: str | None = None) -> None:
        """Send a response without the automatic Server header.

        Routes declare their own Server header when a test needs one. Suppressing
        the standard header keeps the response free of duplicate values.
        """

        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")

    def do_TRACE(self) -> None:
        self._dispatch("TRACE")

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path
        route = self.routes.get(f"{method} {path}")
        if route is None and method in {"GET", "HEAD"}:
            route = self.routes.get(path)
        if route is None:
            self._send(405 if method not in {"GET", "HEAD"} else 404, b"Not Found", [("Content-Type", "text/plain")])
            return
        if callable(route):
            route = route(self, method)
        self._send(*route)

    def _send(
        self,
        status: int,
        body: bytes | str,
        headers: list[tuple[str, str]],
    ) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        applied = list(self.base_headers)
        applied.extend(headers)
        names = {name.lower() for name, _value in applied}
        if "content-type" not in names:
            applied.append(("Content-Type", "text/html; charset=utf-8"))
        for name, value in applied:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def log_message(self, format: str, *args) -> None:
        pass


class RunningServer:
    """A loopback HTTP or HTTPS server with a URL and clean shutdown."""

    def __init__(
        self,
        routes: dict[str, Route],
        base_headers: list[tuple[str, str]] | None = None,
        tls: tuple[str, str] | None = None,
    ) -> None:
        handler = type(
            "ConfiguredHandler",
            (RouteHandler,),
            {
                "routes": routes,
                "base_headers": list(base_headers or []),
            },
        )
        self.httpd = QuietHTTPServer(("127.0.0.1", 0), handler)
        if tls is not None:
            import ssl

            certificate, key = tls
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certificate, keyfile=key)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        else:
            self.scheme = "http"
        self.url = f"{self.scheme}://127.0.0.1:{self.httpd.server_port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> RunningServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=2)


def make_response(
    url: str,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | str = b"",
    redirect_chain: list[str] | None = None,
    tls: TlsInfo | None = None,
):
    """Build an HttpResponse with normalised headers for unit tests."""

    from web_guard.http_client import HttpResponse

    if isinstance(body, str):
        body = body.encode("utf-8")
    header_map: dict[str, list[str]] = {}
    for name, value in headers or []:
        header_map.setdefault(name.lower(), []).append(value)
    if "content-type" not in header_map:
        header_map["content-type"] = ["text/html; charset=utf-8"]
    return HttpResponse(
        url=url,
        status=status,
        reason="",
        headers=header_map,
        body=body,
        elapsed_ms=1.0,
        redirect_chain=tuple(redirect_chain or [url]),
        tls=tls,
        http_version="HTTP/1.1",
    )


class FakeClient:
    """A stub HttpClient whose responses are supplied by a callable."""

    def __init__(self, handler: Callable[[str, str, dict[str, str] | None], object]) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ):
        self.calls.append((url, method, dict(headers or {})))
        result = self.handler(url, method, headers)
        if isinstance(result, Exception):
            raise result
        if result is None:
            raise RequestError(f"No fake response configured for {method} {url}")
        return result


def make_context(
    url: str = "https://example.test/",
    final_url: str | None = None,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | str = b"",
    html: str | None = None,
    tls: TlsInfo | None = None,
    not_found=None,
    client=None,
    settings=None,
    redirect_chain: list[str] | None = None,
):
    """Build a ScanContext for unit testing a single check."""

    from web_guard.check_base import ScanContext
    from web_guard.config import Settings
    from web_guard.html import parse_html
    from web_guard.models import Detection
    from web_guard.target import target_from_input

    target = target_from_input(url)
    final = final_url or url
    payload = html if html is not None else body
    response = make_response(
        final,
        status=status,
        headers=headers,
        body=payload,
        redirect_chain=redirect_chain,
        tls=tls,
    )
    page = parse_html(html) if html is not None else None
    detection = Detection(
        requested_url=url,
        final_url=final,
        status_code=status,
        title=page.title if page else "",
        content_type=response.content_type,
        content_length=len(response.body),
        redirect_chain=response.redirect_chain,
        tls=tls,
    )
    if client is None:
        client = FakeClient(lambda *_args: None)
    return ScanContext(
        target=target,
        response=response,
        client=client,
        settings=settings or Settings(delay=0, timeout=2, probe_tls=False),
        detection=detection,
        page=page,
        not_found=not_found,
    )
