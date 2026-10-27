"""Exception hierarchy used across Web Guard.

The public API raises a small number of explicit exceptions so that the command
line interface can translate failures into stable exit codes and readable error
messages. Internal checks never abort a scan; their failures are captured and
reported as check errors instead.
"""

from __future__ import annotations


class WebGuardError(Exception):
    """Base class for every error intentionally raised by Web Guard."""


class TargetError(WebGuardError):
    """Raised when a target URL is missing, malformed or out of scope."""


class ConfigError(WebGuardError):
    """Raised when configuration values are invalid or inconsistent."""


class RequestError(WebGuardError):
    """Raised when an HTTP request cannot be completed."""


class ScanError(WebGuardError):
    """Raised when the initial target request fails and no audit is possible."""


class CheckError(WebGuardError):
    """Raised by a check when it cannot perform its work."""


class CheckSkipped(WebGuardError):
    """Raised by a check when the target makes the check inapplicable."""
