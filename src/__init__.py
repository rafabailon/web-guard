"""Web Guard public package interface."""

from __future__ import annotations

from .config import Settings
from .errors import (
    CheckError,
    CheckSkipped,
    ConfigError,
    RequestError,
    ScanError,
    TargetError,
    WebGuardError,
)
from .models import (
    CheckOutcome,
    CheckStatus,
    Detection,
    Finding,
    ScanResult,
    Severity,
    TlsInfo,
)
from .report import render_json, render_markdown
from .scanner import scan
from .target import normalize_target, target_from_input
from .version import __version__

__all__ = [
    "CheckError",
    "CheckOutcome",
    "CheckSkipped",
    "CheckStatus",
    "ConfigError",
    "Detection",
    "Finding",
    "RequestError",
    "ScanError",
    "ScanResult",
    "Settings",
    "Severity",
    "TargetError",
    "TlsInfo",
    "WebGuardError",
    "__version__",
    "normalize_target",
    "render_json",
    "render_markdown",
    "scan",
    "target_from_input",
]
