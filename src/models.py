"""Data model shared by the scanner, the checks and the report writers.

All values stored here are deliberately serialisable. The model never keeps raw
response bodies, cookie values or authentication material, which keeps reports
safe to share and prevents accidental secret leakage.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels used for findings and risk calculations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Return a numeric rank where critical is the highest value."""

        return {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name."""

        normalised = value.strip().lower()
        for severity in cls:
            if severity.value == normalised:
                return severity
        allowed = ", ".join(item.value for item in cls)
        raise ValueError(f"Unknown severity '{value}'. Expected one of: {allowed}.")

    @classmethod
    def ordered(cls) -> tuple[Severity, ...]:
        """Return all severities from the most to the least severe."""

        return (cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO)


@dataclass(frozen=True)
class Finding:
    """A single security issue with evidence and remediation guidance.

    The identifier is stable and machine friendly, for example
    ``headers.csp.missing``. The check field names the producing check. The
    evidence string must never contain secrets, only harmless metadata and
    header values that are safe to disclose.
    """

    id: str
    check: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    remediation: str
    references: tuple[str, ...] = ()
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the finding."""

        return {
            "id": self.id,
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
            "cwe": self.cwe,
        }


class CheckStatus(str, Enum):
    """Final state of an individual check."""

    PASSED = "passed"
    ISSUES = "issues"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class CheckOutcome:
    """The result of running one check, including timing and failure details."""

    check_id: str
    name: str
    status: CheckStatus
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the outcome."""

        return {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass(frozen=True)
class TlsInfo:
    """TLS parameters observed for the target or its HTTPS endpoint."""

    available: bool
    verified: bool = False
    version: str = ""
    cipher: str = ""
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    alt_names: tuple[str, ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the TLS information."""

        return {
            "available": self.available,
            "verified": self.verified,
            "version": self.version,
            "cipher": self.cipher,
            "issuer": self.issuer,
            "subject": self.subject,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_remaining": self.days_remaining,
            "alt_names": list(self.alt_names),
            "error": self.error,
        }

    @property
    def summary(self) -> str:
        """Return a compact human readable summary for reports."""

        if not self.available:
            return "Not available"
        parts = [self.version or "TLS"]
        if self.cipher:
            parts.append(self.cipher)
        if self.issuer:
            parts.append(f"issuer {self.issuer}")
        if self.days_remaining is not None:
            parts.append(f"{self.days_remaining} days remaining")
        if not self.verified:
            parts.append("not trusted")
        return ", ".join(parts)


@dataclass(frozen=True)
class Detection:
    """Fingerprint of the target collected before the checks run."""

    requested_url: str
    final_url: str
    status_code: int
    title: str = ""
    ip_address: str = ""
    server: str = ""
    powered_by: str = ""
    content_type: str = ""
    content_length: int = 0
    http_version: str = ""
    response_time_ms: float = 0.0
    redirect_chain: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    tls: TlsInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the fingerprint."""

        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "title": self.title,
            "ip_address": self.ip_address,
            "server": self.server,
            "powered_by": self.powered_by,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "http_version": self.http_version,
            "response_time_ms": round(self.response_time_ms, 3),
            "redirect_chain": list(self.redirect_chain),
            "technologies": list(self.technologies),
            "tls": self.tls.to_dict() if self.tls else None,
        }


@dataclass
class ScanResult:
    """Complete outcome of one audit run."""

    target: str
    final_url: str
    started_at: datetime
    duration_seconds: float
    detection: Detection
    outcomes: list[CheckOutcome]
    findings: list[Finding]
    score: int
    grade: str
    risk: str
    tool_version: str
    checks_requested: tuple[str, ...] = ()
    request_count: int = 0
    settings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None:
            self.started_at = self.started_at.replace(tzinfo=UTC)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings per severity, including zero entries."""

        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        """Return the most severe finding level present, if any."""

        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda item: item.rank)

    def has_at_least(self, threshold: Severity) -> bool:
        """Return true when at least one finding meets or exceeds the threshold."""

        return any(finding.severity.rank >= threshold.rank for finding in self.findings)

    def sorted_findings(self) -> list[Finding]:
        """Return findings ordered by severity and identifier."""

        return sorted(self.findings, key=lambda item: (-item.severity.rank, item.id))

    def outcomes_by_status(self, status: CheckStatus) -> list[CheckOutcome]:
        """Return outcomes matching a status, preserving check order."""

        return [outcome for outcome in self.outcomes if outcome.status is status]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the whole scan."""

        return {
            "tool": "web-guard",
            "tool_version": self.tool_version,
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "score": self.score,
            "grade": self.grade,
            "risk": self.risk,
            "request_count": self.request_count,
            "checks_requested": list(self.checks_requested),
            "settings": dict(self.settings),
            "detection": self.detection.to_dict(),
            "severity_counts": self.severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


def flatten_findings(outcomes: Iterable[CheckOutcome]) -> list[Finding]:
    """Collect findings from outcomes into a single list."""

    findings: list[Finding] = []
    for outcome in outcomes:
        findings.extend(outcome.findings)
    return findings
