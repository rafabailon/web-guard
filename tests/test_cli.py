"""Tests for the command line interface."""

from __future__ import annotations

import runpy
import sys

import pytest
from web_guard.cli import main
from web_guard.version import __version__


def headers_only_routes():
    return {
        "/": (
            200,
            "<!doctype html><html><head><title>CLI target</title></head><body>ok</body></html>",
            [("Content-Type", "text/html; charset=utf-8")],
        )
    }


def test_version_command_prints_the_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"Web Guard {__version__}"


def test_module_entry_point_runs_the_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["web-guard", "version"])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("web_guard", run_name="__main__")
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"Web Guard {__version__}"


def test_checks_command_lists_the_catalogue(capsys):
    assert main(["checks"]) == 0
    output = capsys.readouterr().out
    assert "Available checks (9)" in output
    for identifier in (
        "transport",
        "headers",
        "cookies",
        "cors",
        "methods",
        "disclosure",
        "content",
        "files",
        "wellknown",
    ):
        assert identifier in output


def test_scan_writes_a_markdown_report(serve, tmp_path, capsys):
    server = serve(headers_only_routes())
    output = tmp_path / "audit.md"
    code = main(
        [
            "scan",
            server.url,
            "--checks",
            "headers",
            "--fail-on",
            "none",
            "--delay",
            "0",
            "--no-tls-probe",
            "--no-color",
            "-o",
            str(output),
        ]
    )
    assert code == 0
    assert output.is_file()
    report = output.read_text(encoding="utf-8")
    assert "# Web Guard Security Audit" in report
    assert "CLI target" in report
    assert "HTTP security headers" in report
    captured = capsys.readouterr()
    assert "Scanning" in captured.err
    assert "Report:" in captured.out


def test_scan_can_write_to_standard_output(serve, capsys):
    server = serve(headers_only_routes())
    code = main(
        [
            "scan",
            server.url,
            "--checks",
            "headers",
            "--fail-on",
            "none",
            "--delay",
            "0",
            "--no-tls-probe",
            "-o",
            "-",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "# Web Guard Security Audit" in captured.out
    assert "Report:" not in captured.out


def test_scan_writes_both_formats(serve, tmp_path):
    server = serve(headers_only_routes())
    base = tmp_path / "combined"
    code = main(
        [
            "scan",
            server.url,
            "--checks",
            "headers",
            "--fail-on",
            "none",
            "--delay",
            "0",
            "--no-tls-probe",
            "--format",
            "both",
            "-o",
            str(base),
        ]
    )
    assert code == 0
    assert base.with_suffix(".md").is_file()
    assert base.with_suffix(".json").is_file()


def test_failure_threshold_returns_exit_code_two(serve, tmp_path):
    server = serve(
        {
            "/.env": (200, "SECRET_KEY=test-value\n", [("Content-Type", "text/plain")]),
        }
    )
    code = main(
        [
            "scan",
            server.url,
            "--checks",
            "files",
            "--fail-on",
            "high",
            "--delay",
            "0",
            "--no-tls-probe",
            "--quiet",
            "-o",
            str(tmp_path / "threshold.md"),
        ]
    )
    assert code == 2


def test_invalid_target_returns_exit_code_one(capsys):
    assert main(["scan", "ftp://example.test/"]) == 1
    assert "Only http and https" in capsys.readouterr().err


def test_missing_target_returns_exit_code_one(capsys):
    assert main(["scan"]) == 1
    assert "target URL is required" in capsys.readouterr().err


def test_unknown_check_returns_exit_code_one(serve, capsys):
    server = serve(headers_only_routes())
    assert main(["scan", server.url, "--checks", "unknown-check"]) == 1
    assert "Unknown check identifier" in capsys.readouterr().err


def test_list_checks_does_not_require_a_target(capsys):
    assert main(["scan", "--list-checks"]) == 0
    assert "Available checks (9)" in capsys.readouterr().out


def test_configuration_file_is_applied(serve, tmp_path):
    server = serve(headers_only_routes())
    config = tmp_path / "web-guard.toml"
    config.write_text(
        '[checks]\ninclude = ["cookies"]\n\n[report]\nfail_on = "none"\n',
        encoding="utf-8",
    )
    output = tmp_path / "configured.md"
    code = main(
        [
            "scan",
            server.url,
            "--config",
            str(config),
            "--delay",
            "0",
            "--no-tls-probe",
            "-o",
            str(output),
        ]
    )
    assert code == 0
    report = output.read_text(encoding="utf-8")
    assert "Cookie security" in report
    assert "HTTP security headers" not in report
