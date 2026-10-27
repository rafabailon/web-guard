"""Shared context and base class for audit checks.

A check receives an immutable view of the scan context and returns findings. It
must not mutate the context, keep global state or raise for ordinary site
behaviour. Raising CheckSkipped marks the check as not applicable, while any
other exception is caught by the scanner and reported as a check error without
discarding the rest of the audit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .config import Settings
from .html import PageInfo
from .http_client import HttpClient, HttpResponse
from .models import Detection, Finding
from .target import Target


@dataclass
class ScanContext:
    """Read-only information available to every check during one scan."""

    target: Target
    response: HttpResponse
    client: HttpClient
    settings: Settings
    detection: Detection
    page: PageInfo | None
    not_found: HttpResponse | None = None

    @property
    def final_url(self) -> str:
        """Return the URL of the response that checks operate on."""

        return self.response.url

    @property
    def document_base(self) -> str:
        """Return the effective base URL for resolving page references."""

        if self.page and self.page.base_href:
            return urljoin(self.final_url, self.page.base_href)
        return self.final_url

    def absolute_url(self, reference: str) -> str:
        """Resolve a page reference against the document base."""

        return urljoin(self.document_base, reference)

    def same_origin(self, url: str) -> bool:
        """Return true when a URL shares scheme, host and port with the target."""

        left = urlsplit(self.final_url)
        right = urlsplit(url)
        try:
            left_port = left.port or (443 if left.scheme == "https" else 80)
            right_port = right.port or (443 if right.scheme == "https" else 80)
        except ValueError:
            return False
        return (
            left.scheme == right.scheme
            and (left.hostname or "").lower() == (right.hostname or "").lower()
            and left_port == right_port
        )


class Check(ABC):
    """Base class for all audit checks."""

    id: str = ""
    name: str = ""
    description: str = ""
    order: int = 100

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        """Run the check and return zero or more findings."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id!r}>"
