"""Configuration loading and validation.

Settings are immutable and validated once at startup. The command line accepts
a TOML file, and explicit command line options always win over file values. The
configuration intentionally covers only transport and reporting behaviour; the
list of checks is handled separately so that a typo cannot silently disable a
security test.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import ConfigError
from .models import Severity
from .version import __version__

DEFAULT_USER_AGENT = (
    f"WebGuard/{__version__} (defensive security audit; "
    "contact the site owner before scanning)"
)

DEFAULT_TIMEOUT = 10.0
DEFAULT_DELAY = 0.25
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_BODY_BYTES = 2_097_152
DEFAULT_CORS_ORIGIN = "https://webguard.invalid"


@dataclass(frozen=True)
class Settings:
    """Validated runtime settings for a scan."""

    timeout: float = DEFAULT_TIMEOUT
    delay: float = DEFAULT_DELAY
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    probe_tls: bool = True
    cors_origin: str = DEFAULT_CORS_ORIGIN

    def __post_init__(self) -> None:
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise ConfigError("timeout must be a number.")
        if not 0.1 <= float(self.timeout) <= 120:
            raise ConfigError("timeout must be between 0.1 and 120 seconds.")
        if isinstance(self.delay, bool) or not isinstance(self.delay, (int, float)):
            raise ConfigError("delay must be a number.")
        if not 0 <= float(self.delay) <= 60:
            raise ConfigError("delay must be between 0 and 60 seconds.")
        if isinstance(self.max_redirects, bool) or not isinstance(self.max_redirects, int):
            raise ConfigError("max_redirects must be an integer.")
        if not 0 <= self.max_redirects <= 50:
            raise ConfigError("max_redirects must be between 0 and 50.")
        if isinstance(self.max_body_bytes, bool) or not isinstance(self.max_body_bytes, int):
            raise ConfigError("max_body_bytes must be an integer.")
        if not 1024 <= self.max_body_bytes <= 20_971_520:
            raise ConfigError("max_body_bytes must be between 1024 and 20971520.")
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise ConfigError("user_agent must be a non-empty string.")
        if "\r" in self.user_agent or "\n" in self.user_agent:
            raise ConfigError("user_agent must not contain line breaks.")
        if not isinstance(self.verify_tls, bool):
            raise ConfigError("verify_tls must be a boolean.")
        if not isinstance(self.probe_tls, bool):
            raise ConfigError("probe_tls must be a boolean.")
        if not isinstance(self.cors_origin, str):
            raise ConfigError("cors_origin must be a string.")
        parsed_origin = urlsplit(self.cors_origin)
        if parsed_origin.scheme not in {"http", "https"} or not parsed_origin.netloc:
            raise ConfigError("cors_origin must be an absolute http or https origin.")
        if parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment:
            raise ConfigError("cors_origin must not include a path, query or fragment.")

    def to_dict(self) -> dict[str, Any]:
        """Return settings suitable for report metadata."""

        return {
            "timeout": float(self.timeout),
            "delay": float(self.delay),
            "max_redirects": self.max_redirects,
            "max_body_bytes": self.max_body_bytes,
            "user_agent": self.user_agent,
            "verify_tls": self.verify_tls,
            "probe_tls": self.probe_tls,
            "cors_origin": self.cors_origin,
        }


_SCANNER_KEYS = {field.name for field in fields(Settings)}
_TOP_LEVEL_KEYS = {"scanner", "checks", "report"}


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a TOML configuration file with structural validation."""

    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not read {config_path}: {exc}") from exc

    unknown_top_level = set(data) - _TOP_LEVEL_KEYS
    if unknown_top_level:
        names = ", ".join(sorted(unknown_top_level))
        raise ConfigError(f"Unknown top-level configuration section(s): {names}")
    scanner = data.get("scanner", {})
    if not isinstance(scanner, dict):
        raise ConfigError("The scanner section must be a table.")
    unknown_scanner = set(scanner) - _SCANNER_KEYS
    if unknown_scanner:
        names = ", ".join(sorted(unknown_scanner))
        raise ConfigError(f"Unknown scanner setting(s): {names}")
    checks = data.get("checks", {})
    if not isinstance(checks, dict):
        raise ConfigError("The checks section must be a table.")
    report = data.get("report", {})
    if not isinstance(report, dict):
        raise ConfigError("The report section must be a table.")
    return data


def settings_from_config(
    config_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Build settings from defaults, an optional TOML file and CLI overrides."""

    values: dict[str, Any] = {}
    if config_path is not None:
        data = load_config(config_path)
        values.update(data.get("scanner", {}))
    if overrides:
        values.update({key: value for key, value in overrides.items() if value is not None})
    unknown = set(values) - _SCANNER_KEYS
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ConfigError(f"Unknown scanner setting(s): {names}")
    return Settings(**values)


def checks_from_config(config_path: str | Path | None = None) -> tuple[list[str], list[str]]:
    """Return include and exclude check identifiers from a configuration file."""

    if config_path is None:
        return [], []
    data = load_config(config_path)
    checks = data.get("checks", {})
    include = checks.get("include", [])
    exclude = checks.get("exclude", [])
    if not isinstance(include, list) or not all(isinstance(item, str) for item in include):
        raise ConfigError("checks.include must be a list of strings.")
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise ConfigError("checks.exclude must be a list of strings.")
    return include, exclude


def fail_on_from_config(config_path: str | Path | None = None) -> Severity | None:
    """Return the configured failure threshold, defaulting to high.

    The special value ``none`` disables failure exits and is returned as None.
    """

    if config_path is None:
        return Severity.HIGH
    data = load_config(config_path)
    report = data.get("report", {})
    value = report.get("fail_on", Severity.HIGH.value)
    if not isinstance(value, str):
        raise ConfigError("report.fail_on must be a severity name or 'none'.")
    if value.strip().lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def with_overrides(settings: Settings, **overrides: Any) -> Settings:
    """Return a copy of settings with validated overrides applied."""

    return replace(settings, **{key: value for key, value in overrides.items() if value is not None})
