"""Small shared helpers with no security decisions of their own."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TypeVar
from urllib.parse import urljoin, urlsplit, urlunsplit

T = TypeVar("T")

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def unique(items: Iterable[T]) -> list[T]:
    """Return items in first-seen order without duplicates."""

    seen: set[T] = set()
    result: list[T] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def clean_text(value: str, limit: int = 500) -> str:
    """Replace control characters and shorten untrusted display text."""

    cleaned = _CONTROL_CHARACTERS.sub(" ", value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        return f"{cleaned[: limit - 1]}…"
    return cleaned


def resolve_url(base: str, reference: str) -> str:
    """Resolve a possibly relative reference against a base URL."""

    return urljoin(base, reference)


def origin_of(url: str) -> str:
    """Return the scheme and authority of a URL."""

    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def url_without_fragment(url: str) -> str:
    """Remove the fragment component from a URL."""

    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def is_http_url(url: str) -> bool:
    """Return true for absolute HTTP and HTTPS URLs."""

    parsed = urlsplit(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def is_http_resource(url: str) -> bool:
    """Return true for absolute plain HTTP resources."""

    parsed = urlsplit(url)
    return parsed.scheme == "http" and bool(parsed.netloc)


def content_type_of(value: str) -> str:
    """Extract the media type from a Content-Type header value."""

    return value.split(";", 1)[0].strip().lower()


def is_html_content_type(value: str) -> bool:
    """Return true when a Content-Type header describes HTML."""

    media_type = content_type_of(value)
    return media_type in {"text/html", "application/xhtml+xml"}


def is_text_content_type(value: str) -> bool:
    """Return true when a Content-Type header is text-like."""

    media_type = content_type_of(value)
    return (
        media_type.startswith("text/")
        or media_type in {"application/json", "application/xml", "application/javascript"}
        or media_type.endswith(("+json", "+xml"))
    )


def host_from_url(url: str) -> str:
    """Return the host component of a URL."""

    return urlsplit(url).hostname or ""


def redact_url(url: str, limit: int = 500) -> str:
    """Remove fragments and redact query values before displaying a URL.

    Paths are preserved because they are needed to understand a finding. Query
    values may contain session identifiers, tokens or personal data, so they are
    replaced while the parameter names remain visible.
    """

    try:
        parsed = urlsplit(url)
    except ValueError:
        return clean_text(url, limit)
    query = ""
    if parsed.query:
        pairs: list[str] = []
        for pair in parsed.query.split("&"):
            key, separator, _value = pair.partition("=")
            pairs.append(f"{key}=REDACTED" if separator else key)
        query = "&".join(pairs)
    redacted = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    return clean_text(redacted, limit)


def format_duration(seconds: float) -> str:
    """Format a duration for human readable reports."""

    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"
