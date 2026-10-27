"""Target URL parsing and normalisation.

The scanner audits exactly one origin per run. Input is normalised before any
network activity so that duplicate slashes in user input, missing schemes and
default ports cannot create inconsistent reports. Credentials embedded in a URL
are rejected because the report would otherwise risk exposing them and because
authenticated scanning is outside the supported scope.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .errors import TargetError

_SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """Normalised target information used by the scanner."""

    url: str
    scheme: str
    host: str
    port: int
    explicit_port: bool
    implicit_scheme: bool

    @property
    def origin(self) -> str:
        """Return the scheme and authority without a path or query."""

        return f"{self.scheme}://{_format_authority(self.host, self.port, self.scheme)}"


def target_from_input(raw: str) -> Target:
    """Parse user input into a normalised target.

    Missing schemes are resolved to HTTPS. The scanner may fall back to HTTP
    when the implicit HTTPS connection fails, but normalisation itself stays
    deterministic so that reports and tests remain stable.
    """

    if not isinstance(raw, str):
        raise TargetError("The target must be a string.")
    if any(character.isspace() for character in raw):
        raise TargetError("The target URL must not contain whitespace.")
    if any(ord(character) < 32 for character in raw):
        raise TargetError("The target URL must not contain control characters.")
    value = raw
    if not value:
        raise TargetError("The target URL is empty.")

    implicit_scheme = not bool(_SCHEME_PREFIX.match(value))
    if implicit_scheme:
        value = f"https://{value.lstrip('/')}"

    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TargetError(f"Invalid target URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetError("Only http and https URLs are supported.")
    if not parsed.netloc:
        raise TargetError("The target URL must include a host.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetError("Credentials in URLs are not supported. Remove the user information section.")
    if not host:
        raise TargetError("The target URL must include a host.")

    host = _normalise_host(host)
    explicit_port = port is not None
    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    if not 1 <= effective_port <= 65535:
        raise TargetError("The port must be between 1 and 65535.")

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    query = parsed.query
    normalised = urlunsplit((scheme, _format_authority(host, effective_port, scheme), path, query, ""))
    return Target(
        url=normalised,
        scheme=scheme,
        host=host,
        port=effective_port,
        explicit_port=explicit_port,
        implicit_scheme=implicit_scheme,
    )


def normalize_target(raw: str) -> str:
    """Return only the normalised URL for callers that do not need metadata."""

    return target_from_input(raw).url


def _normalise_host(host: str) -> str:
    """Normalise DNS names, IPv4 and IPv6 literals."""

    candidate = host.strip().rstrip(".").lower()
    if not candidate:
        raise TargetError("The target host is empty.")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetError("The target host is not a valid DNS name.") from exc
        labels = candidate.split(".")
        if any(not label for label in labels):
            raise TargetError("The target host contains an empty label.")
        for label in labels:
            if len(label) > 63:
                raise TargetError("A target host label exceeds 63 characters.")
            if label.startswith("-") or label.endswith("-"):
                raise TargetError("A target host label must not start or end with a hyphen.")
        if len(candidate) > 253:
            raise TargetError("The target host exceeds 253 characters.")
        allowed = re.compile(r"^[a-z0-9_-]+$")
        if not all(allowed.match(label) for label in labels):
            raise TargetError("The target host contains invalid characters.")
        return candidate
    if isinstance(address, ipaddress.IPv6Address):
        return str(address)
    return str(address)


def _format_authority(host: str, port: int, scheme: str) -> str:
    """Format an authority, omitting default ports and bracketing IPv6."""

    display_host = f"[{host}]" if ":" in host else host
    if port == _DEFAULT_PORTS.get(scheme):
        return display_host
    return f"{display_host}:{port}"
