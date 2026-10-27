"""Tests for check discovery and selection."""

from __future__ import annotations

import pytest
from web_guard.checks import build_checks, check_catalog, check_ids, select_checks
from web_guard.errors import ConfigError

EXPECTED_IDS = [
    "transport",
    "headers",
    "cookies",
    "cors",
    "methods",
    "disclosure",
    "content",
    "files",
    "wellknown",
]


def test_catalogue_is_complete_and_ordered():
    assert check_ids() == EXPECTED_IDS
    catalog = check_catalog()
    assert list(catalog) == EXPECTED_IDS
    assert all(check.name and check.description for check in build_checks())


def test_build_checks_returns_fresh_instances():
    first = build_checks()
    second = build_checks()
    assert [item.id for item in first] == [item.id for item in second]
    assert first[0] is not second[0]


def test_include_selects_only_requested_checks():
    selected = select_checks(["headers", "cookies"])
    assert [check.id for check in selected] == ["headers", "cookies"]


def test_exclude_removes_checks():
    selected = select_checks(exclude=["headers", "files"])
    assert [check.id for check in selected] == ["transport", "cookies", "cors", "methods", "disclosure", "content", "wellknown"]


def test_empty_include_selects_all():
    assert [check.id for check in select_checks()] == EXPECTED_IDS


def test_unknown_check_is_rejected():
    with pytest.raises(ConfigError, match="Unknown check"):
        select_checks(["headers", "nope"])


def test_unknown_excluded_check_is_rejected():
    with pytest.raises(ConfigError, match="Unknown check"):
        select_checks(exclude=["nope"])


def test_overlap_between_include_and_exclude_is_rejected():
    with pytest.raises(ConfigError, match="both included and excluded"):
        select_checks(["headers"], ["headers"])
