"""Check registry and selection helpers.

Checks are instantiated per scan so that no state leaks between runs. Identifiers
are stable and form part of the public configuration contract.
"""

from __future__ import annotations

from .check_base import Check, ScanContext
from .check_content import ContentCheck
from .check_cookies import CookieCheck
from .check_cors import CorsCheck
from .check_disclosure import DisclosureCheck
from .check_headers import HeaderCheck
from .check_methods import MethodCheck
from .check_sensitive_files import SensitiveFilesCheck
from .check_transport import TransportCheck
from .check_wellknown import WellKnownCheck
from .errors import ConfigError

_CHECK_CLASSES: tuple[type[Check], ...] = (
    TransportCheck,
    HeaderCheck,
    CookieCheck,
    CorsCheck,
    MethodCheck,
    DisclosureCheck,
    ContentCheck,
    SensitiveFilesCheck,
    WellKnownCheck,
)


def build_checks() -> list[Check]:
    """Return a fresh, ordered list of all available checks."""

    return [check_class() for check_class in _CHECK_CLASSES]


def check_catalog() -> dict[str, Check]:
    """Return the known checks indexed by identifier."""

    return {check.id: check for check in build_checks()}


def check_ids() -> list[str]:
    """Return all check identifiers in execution order."""

    return [check.id for check in build_checks()]


def select_checks(include: list[str] | None = None, exclude: list[str] | None = None) -> list[Check]:
    """Select checks by identifier, validating names and conflicts."""

    include = include or []
    exclude = exclude or []
    catalog = check_catalog()
    unknown = sorted(set(include + exclude) - set(catalog))
    if unknown:
        names = ", ".join(unknown)
        valid = ", ".join(catalog)
        raise ConfigError(f"Unknown check identifier(s): {names}. Available checks: {valid}.")
    overlap = sorted(set(include) & set(exclude))
    if overlap:
        names = ", ".join(overlap)
        raise ConfigError(f"Check identifier(s) cannot be both included and excluded: {names}.")
    selected = [
        check
        for check in build_checks()
        if (not include or check.id in include) and check.id not in exclude
    ]
    return selected


__all__ = [
    "Check",
    "ScanContext",
    "build_checks",
    "check_catalog",
    "check_ids",
    "select_checks",
]
