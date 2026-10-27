"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from web_guard.config import (
    Settings,
    checks_from_config,
    fail_on_from_config,
    load_config,
    settings_from_config,
    with_overrides,
)
from web_guard.errors import ConfigError
from web_guard.models import Severity


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "web-guard.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_default_settings_are_valid():
    settings = Settings()
    assert settings.timeout == 10.0
    assert settings.delay == 0.25
    assert settings.verify_tls is True
    assert "WebGuard" in settings.user_agent
    assert settings.to_dict()["probe_tls"] is True


@pytest.mark.parametrize(
    "values",
    [
        {"timeout": 0},
        {"timeout": 121},
        {"delay": -1},
        {"delay": 61},
        {"max_redirects": -1},
        {"max_redirects": 51},
        {"max_body_bytes": 10},
        {"max_body_bytes": 30_000_000},
        {"user_agent": ""},
        {"user_agent": "a\nb"},
        {"verify_tls": "yes"},
        {"probe_tls": 1},
        {"cors_origin": "/relative"},
        {"cors_origin": "ftp://example.com"},
        {"cors_origin": "https://example.com/path"},
        {"timeout": True},
        {"max_redirects": True},
    ],
)
def test_invalid_settings_are_rejected(values):
    with pytest.raises(ConfigError):
        Settings(**values)


def test_settings_accept_valid_custom_values():
    settings = Settings(
        timeout=1.5,
        delay=0,
        max_redirects=0,
        max_body_bytes=4096,
        user_agent="Test Agent",
        verify_tls=False,
        probe_tls=False,
        cors_origin="https://example.test",
    )
    assert settings.max_redirects == 0
    assert settings.to_dict()["verify_tls"] is False


def test_load_config_validates_structure(tmp_path):
    path = write_config(
        tmp_path,
        """
[scanner]
timeout = 3.5
delay = 0.1
verify_tls = false

[checks]
include = ["headers", "cookies"]
exclude = ["cors"]

[report]
fail_on = "medium"
""",
    )
    data = load_config(path)
    assert data["scanner"]["timeout"] == 3.5
    settings = settings_from_config(path)
    assert settings.timeout == 3.5
    assert settings.delay == 0.1
    assert settings.verify_tls is False
    assert checks_from_config(path) == (["headers", "cookies"], ["cors"])
    assert fail_on_from_config(path) is Severity.MEDIUM


def test_cli_overrides_win_over_file(tmp_path):
    path = write_config(tmp_path, "[scanner]\ntimeout = 3.5\n")
    settings = settings_from_config(path, {"timeout": 9.0, "delay": 0.5})
    assert settings.timeout == 9.0
    assert settings.delay == 0.5


def test_fail_on_none_disables_threshold(tmp_path):
    path = write_config(tmp_path, "[report]\nfail_on = \"none\"\n")
    assert fail_on_from_config(path) is None


def test_invalid_fail_on_is_rejected(tmp_path):
    path = write_config(tmp_path, "[report]\nfail_on = \"urgent\"\n")
    with pytest.raises(ConfigError):
        fail_on_from_config(path)


def test_unknown_top_level_section_is_rejected(tmp_path):
    path = write_config(tmp_path, "[scanner]\ntimeout = 3\n\n[unknown]\nx = 1\n")
    with pytest.raises(ConfigError, match="Unknown top-level"):
        load_config(path)


def test_unknown_scanner_key_is_rejected(tmp_path):
    path = write_config(tmp_path, "[scanner]\ntimeuot = 3\n")
    with pytest.raises(ConfigError, match="Unknown scanner"):
        load_config(path)


def test_invalid_toml_is_rejected(tmp_path):
    path = write_config(tmp_path, "[scanner\n")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config(path)


def test_missing_config_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")


def test_invalid_check_lists_are_rejected(tmp_path):
    path = write_config(tmp_path, "[checks]\ninclude = \"headers\"\n")
    with pytest.raises(ConfigError, match="checks.include"):
        checks_from_config(path)


def test_with_overrides_returns_new_validated_settings():
    settings = Settings()
    changed = with_overrides(settings, timeout=2.0, delay=None)
    assert changed.timeout == 2.0
    assert changed.delay == settings.delay
    assert settings.timeout == 10.0
