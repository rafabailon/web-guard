"""HTTP and TLS primitives used by the scanner.

The client is built on the standard library so that Web Guard has no runtime
dependencies. Redirects are followed manually to record the complete chain and
to apply a hard limit. Response bodies are truncated, certificates are inspected
when available, and every request passes through a small rate limiter. No cookie
jar is kept because the scanner is not a browser and must not maintain a session.
"""

from __future__ import annotations

import http.client
import math
import re
import socket
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit, urlunsplit

from .config import Settings
from .errors import RequestError
from .models import TlsInfo
from .utils import content_type_of

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_CHARSET_PATTERN = re.compile(r"charset\s*=\s*[\"']?([^;\"'\s]+)", re.IGNORECASE)
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "MD5", "EXPORT", "anon")


@dataclass
class HttpResponse:
    """A bounded, immutable-on-read HTTP response representation."""

    url: str
    status: int
    reason: str
    headers: dict[str, list[str]]
    body: bytes = b""
    elapsed_ms: float = 0.0
    redirect_chain: tuple[str, ...] = ()
    tls: TlsInfo | None = None
    http_version: str = ""
    truncated: bool = False

    def header(self, name: str, default: str = "") -> str:
        """Return a header value, joining repeated headers with a comma."""

        values = self.headers.get(name.lower(), [])
        if not values:
            return default
        return ", ".join(values)

    def header_values(self, name: str) -> list[str]:
        """Return all values for a header without folding them."""

        return list(self.headers.get(name.lower(), []))

    @property
    def text(self) -> str:
        """Decode the body using the declared charset or UTF-8."""

        charset = "utf-8"
        match = _CHARSET_PATTERN.search(self.header("content-type"))
        if match:
            charset = match.group(1)
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        """Return the response media type without parameters."""

        return content_type_of(self.header("content-type"))

    @property
    def cookies(self) -> list[str]:
        """Return raw Set-Cookie header values for inspection."""

        return self.header_values("set-cookie")

    @property
    def is_redirect(self) -> bool:
        """Return true when the response is a redirect with a location."""

        return self.status in _REDIRECT_STATUSES and bool(self.header("location"))


@dataclass
class _RawResponse:
    """Internal result of one request before redirect handling."""

    url: str
    status: int
    reason: str
    headers: dict[str, list[str]]
    body: bytes
    elapsed_ms: float
    tls: TlsInfo | None
    http_version: str
    truncated: bool = False


class HttpClient:
    """A small HTTP client with explicit redirects, limits and rate limiting."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.request_count = 0
        self._last_request_at = 0.0

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        """Perform a request and follow redirects up to the configured limit."""

        method = method.upper()
        chain = [url]
        seen = {_normalise_for_loop_detection(url)}
        current = url
        started = time.perf_counter()

        while True:
            raw = self._request_once(current, method, headers, body)
            redirect_count = len(chain) - 1
            if not _is_redirect(raw.status, raw):
                elapsed = (time.perf_counter() - started) * 1000
                return HttpResponse(
                    url=raw.url,
                    status=raw.status,
                    reason=raw.reason,
                    headers=raw.headers,
                    body=raw.body,
                    elapsed_ms=elapsed,
                    redirect_chain=tuple(chain),
                    tls=raw.tls,
                    http_version=raw.http_version,
                    truncated=raw.truncated,
                )

            if redirect_count >= self.settings.max_redirects:
                raise RequestError(
                    f"Too many redirects while requesting {url} "
                    f"(limit {self.settings.max_redirects})."
                )
            location = _header_value(raw.headers, "location")
            target = urljoin(current, location).split("#", 1)[0]
            _validate_request_url(target)
            loop_key = _normalise_for_loop_detection(target)
            if loop_key in seen:
                raise RequestError(f"Redirect loop detected while requesting {url}.")
            seen.add(loop_key)
            chain.append(target)
            current = target
            if raw.status == 303 or (raw.status in {301, 302} and method == "POST"):
                method = "GET"
                body = None

    def _request_once(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str] | None,
        body: bytes | None,
    ) -> _RawResponse:
        """Execute a single request without following redirects."""

        parsed = _validate_request_url(url)
        host = parsed.hostname
        if not host:
            raise RequestError(f"Request URL has no host: {url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        request_headers = _merge_headers(self.settings.user_agent, headers)
        request_headers["Host"] = _authority(host, port, parsed.scheme)

        self._throttle()
        started = time.perf_counter()
        connection: http.client.HTTPConnection | None = None
        try:
            if parsed.scheme == "https":
                context = _ssl_context(self.settings.verify_tls)
                connection = http.client.HTTPSConnection(host, port, timeout=self.settings.timeout, context=context)
            else:
                connection = http.client.HTTPConnection(host, port, timeout=self.settings.timeout)
            self.request_count += 1
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            limit = self.settings.max_body_bytes
            raw_body = response.read(limit + 1)
            truncated = len(raw_body) > limit
            if truncated:
                raw_body = raw_body[:limit]
            header_map: dict[str, list[str]] = {}
            for name, value in response.getheaders():
                header_map.setdefault(name.lower(), []).append(value)
            tls_info = None
            if parsed.scheme == "https" and connection.sock is not None:
                tls_info = _tls_info_from_socket(
                    connection.sock,
                    verified=self.settings.verify_tls,
                )
            elapsed_ms = (time.perf_counter() - started) * 1000
            return _RawResponse(
                url=url,
                status=response.status,
                reason=response.reason or "",
                headers=header_map,
                body=raw_body,
                elapsed_ms=elapsed_ms,
                tls=tls_info,
                http_version=_http_version(response.version),
                truncated=truncated,
            )
        except ssl.SSLCertVerificationError as exc:
            detail = exc.verify_message or str(exc)
            raise RequestError(
                f"TLS certificate verification failed for {parsed.hostname}: {detail}. "
                "Use --insecure only after confirming the target is trusted."
            ) from exc
        except ssl.SSLError as exc:
            raise RequestError(f"TLS error while requesting {url}: {exc}") from exc
        except TimeoutError as exc:
            raise RequestError(f"Request timed out after {self.settings.timeout} seconds: {url}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise RequestError(f"Request failed for {url}: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()

    def _throttle(self) -> None:
        """Sleep as needed to keep the configured delay between requests."""

        if self.settings.delay <= 0:
            return
        now = time.monotonic()
        wait = self.settings.delay - (now - self._last_request_at)
        if self._last_request_at and wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()


def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> TlsInfo:
    """Inspect an HTTPS endpoint without HTTP, retaining certificate details.

    A verified handshake is attempted first. If the certificate is rejected, a
    second unverified handshake retrieves protocol and cipher information while
    keeping the trust failure visible in the returned object. Connection errors
    produce an unavailable result instead of raising, because a missing HTTPS
    endpoint is itself a useful audit observation.
    """

    error = ""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket, context.wrap_socket(
            raw_socket, server_hostname=host
        ) as tls_socket:
            return _tls_info_from_socket(tls_socket, verified=True)
    except ssl.SSLCertVerificationError as exc:
        error = exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        error = str(exc)
    except TimeoutError as exc:
        return TlsInfo(available=False, error=f"TLS connection timed out: {exc}")
    except OSError as exc:
        return TlsInfo(available=False, error=str(exc))

    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket, unverified.wrap_socket(
            raw_socket, server_hostname=host
        ) as tls_socket:
            return _tls_info_from_socket(tls_socket, verified=False, error=error)
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        return TlsInfo(available=False, error=error or str(exc))


def is_weak_cipher(cipher: str) -> bool:
    """Return true for cipher names containing known weak components."""

    upper = cipher.upper()
    return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)


def tls_probe_target(url: str) -> tuple[str, int] | None:
    """Return host and port to probe for HTTPS when the target itself is HTTP.

    A standalone probe is only meaningful on the standard cleartext port. On a
    custom port the HTTPS service cannot be assumed to share that port, so the
    caller receives None and the report simply states that HTTPS is not in use.
    """

    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.port not in (None, 80):
        return None
    return parsed.hostname or "", 443


def _ssl_context(verify: bool) -> ssl.SSLContext:
    """Build a client TLS context that optionally skips verification."""

    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _merge_headers(user_agent: str, custom: Mapping[str, str] | None) -> dict[str, str]:
    """Merge default headers with caller supplied headers, case-insensitively."""

    merged: dict[str, str] = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if not custom:
        return merged
    lowered = {key.lower() for key in custom}
    merged = {key: value for key, value in merged.items() if key.lower() not in lowered}
    merged.update(dict(custom))
    return merged


def _validate_request_url(url: str):
    """Parse and validate a URL immediately before a request."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise RequestError(f"Invalid URL: {url} ({exc})") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RequestError(f"Only absolute http and https URLs can be requested: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise RequestError("Redirects to URLs with embedded credentials are not followed.")
    if port is not None and not 1 <= port <= 65535:
        raise RequestError(f"Invalid port in URL: {url}")
    return parsed


def _authority(host: str, port: int, scheme: str) -> str:
    """Build the Host header value, including non-default ports."""

    display = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return display if port == default else f"{display}:{port}"


def _normalise_for_loop_detection(url: str) -> str:
    """Normalise a URL just enough to detect trivial redirect loops."""

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    display = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        display = f"{display}:{port}"
    return urlunsplit((scheme, display, parsed.path or "/", parsed.query, ""))


def _is_redirect(status: int, raw: _RawResponse) -> bool:
    """Return true when a raw response is a redirect with a location."""

    return status in _REDIRECT_STATUSES and bool(_header_value(raw.headers, "location"))


def _header_value(headers: dict[str, list[str]], name: str) -> str:
    """Return the first value of a header from a raw header map."""

    values = headers.get(name.lower(), [])
    return values[0] if values else ""


def _http_version(version: int) -> str:
    """Map http.client protocol numbers to readable version strings."""

    return {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2.0"}.get(version, f"HTTP/{version}")


def _tls_info_from_socket(socket_object, verified: bool, error: str = "") -> TlsInfo:
    """Extract TLS metadata from an active socket."""

    certificate: dict = {}
    try:
        certificate = socket_object.getpeercert() or {}
    except (ValueError, OSError):
        certificate = {}
    version = socket_object.version() or ""
    cipher_name = ""
    try:
        cipher = socket_object.cipher()
        cipher_name = cipher[0] if cipher else ""
    except (ValueError, OSError):
        cipher_name = ""

    issuer = _distinguished_name(certificate.get("issuer", ()))
    subject = _distinguished_name(certificate.get("subject", ()))
    not_before, not_after, days_remaining = _certificate_dates(certificate)
    alt_names = tuple(
        value for key, value in certificate.get("subjectAltName", ()) if key.lower() in {"dns", "ip address"}
    )
    if not certificate and not error:
        error = "The peer did not present a readable certificate."
    return TlsInfo(
        available=True,
        verified=verified,
        version=version,
        cipher=cipher_name,
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        alt_names=alt_names,
        error=error,
    )


def _distinguished_name(parts) -> str:
    """Flatten the tuple structure returned by ssl.getpeercert()."""

    items: list[str] = []
    for relative_name in parts:
        for key, value in relative_name:
            items.append(f"{key}={value}")
    return ", ".join(items)


def _certificate_dates(certificate: dict) -> tuple[str, str, int | None]:
    """Return readable certificate dates and remaining whole days."""

    not_before_raw = certificate.get("notBefore", "")
    not_after_raw = certificate.get("notAfter", "")
    not_after_epoch = 0
    if not_after_raw:
        try:
            not_after_epoch = int(ssl.cert_time_to_seconds(not_after_raw))
        except ValueError:
            not_after_epoch = 0
    if not_after_epoch:
        not_after = datetime.fromtimestamp(not_after_epoch, tz=UTC).strftime("%Y-%m-%d")
        days = math.floor((not_after_epoch - datetime.now(tz=UTC).timestamp()) / 86400)
    else:
        not_after = str(not_after_raw)
        days = None
    return str(not_before_raw), not_after, days
