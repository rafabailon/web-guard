"""Command line interface for Web Guard.

The CLI is intentionally small: one scan command, one catalogue command and one
version command. Configuration can come from a TOML file and is always
overridden by explicit options. Exit code zero means the scan completed and no
finding reached the failure threshold, one means the scan could not complete,
and two means the threshold was reached.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from .checks import check_catalog, select_checks
from .config import (
    Settings,
    checks_from_config,
    fail_on_from_config,
    settings_from_config,
)
from .errors import ConfigError, ScanError, TargetError
from .models import ScanResult, Severity
from .report import render_json, render_markdown
from .scanner import scan
from .target import target_from_input
from .version import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2
EXIT_INTERRUPTED = 130


def main(argv: list[str] | None = None) -> int:
    """Run the command line interface and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"Web Guard {__version__}")
        return EXIT_OK
    if args.command == "checks":
        _print_checks()
        return EXIT_OK
    if args.command != "scan":
        parser.print_help()
        return EXIT_ERROR

    _configure_logging(bool(args.verbose), bool(args.quiet))
    if args.list_checks:
        _print_checks()
        return EXIT_OK
    if not args.target:
        print("error: a target URL is required unless --list-checks is used.", file=sys.stderr)
        return EXIT_ERROR
    if args.insecure and not args.quiet:
        print(
            "warning: TLS certificate verification is disabled for this scan.",
            file=sys.stderr,
        )

    try:
        settings, include, exclude, fail_on = _build_run_config(args)
        target = target_from_input(args.target)
        selected = select_checks(include, exclude)
        print(f"Scanning {target.url} with {len(selected)} checks...", file=sys.stderr)
        result = scan(args.target, settings=settings, checks=selected)
        outputs = _write_outputs(result, args, target)
        if not args.quiet and args.output != "-":
            _print_summary(result, outputs, args.no_color)
        if fail_on is not None and result.has_at_least(fail_on):
            if not args.quiet:
                print(
                    f"Findings at or above '{fail_on.value}' were detected; "
                    f"failure threshold reached.",
                    file=sys.stderr,
                )
            return EXIT_THRESHOLD
        return EXIT_OK
    except (ConfigError, TargetError, ScanError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            logging.getLogger(__name__).debug("Command failed", exc_info=True)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser used by the console entry point."""

    parser = argparse.ArgumentParser(
        prog="web-guard",
        description="Defensive web security audit with Markdown reports.",
        epilog=(
            "Examples: web-guard scan https://example.com -o report.md; "
            "web-guard scan example.com --checks headers,cookies --fail-on none; "
            "web-guard checks"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Web Guard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Audit a single web target.",
        description="Audit one HTTP or HTTPS target and write a Markdown report.",
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        help="Target URL. HTTPS is assumed when the scheme is omitted.",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Report path. Use '-' to write to standard output. Defaults to a timestamped file.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("md", "json", "both"),
        default="md",
        help="Report format. 'both' writes a Markdown and a JSON file. Default: md.",
    )
    scan_parser.add_argument("--config", help="Path to a TOML configuration file.")
    scan_parser.add_argument(
        "--checks",
        help="Comma separated check identifiers to include. Default: all checks.",
    )
    scan_parser.add_argument(
        "--exclude-checks",
        help="Comma separated check identifiers to exclude.",
    )
    scan_parser.add_argument("--list-checks", action="store_true", help="List checks and exit.")
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "info", "low", "medium", "high", "critical"),
        help="Exit with code 2 when a finding at or above this severity exists. Default: high.",
    )
    scan_parser.add_argument("--timeout", type=float, help="Per-request timeout in seconds.")
    scan_parser.add_argument("--delay", type=float, help="Delay between requests in seconds.")
    scan_parser.add_argument("--max-redirects", type=int, help="Maximum redirects to follow.")
    scan_parser.add_argument("--max-body-bytes", type=int, help="Maximum response body bytes to inspect.")
    scan_parser.add_argument("--user-agent", help="User-Agent header for audit requests.")
    scan_parser.add_argument("--cors-origin", help="Origin value used for the CORS probe.")
    scan_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Use only after confirming the target is trusted.",
    )
    scan_parser.add_argument(
        "--no-tls-probe",
        action="store_true",
        help="Do not probe port 443 when the target itself is served over HTTP.",
    )
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress the terminal summary.")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours.")

    subparsers.add_parser(
        "checks",
        help="List available checks.",
        description="List every check identifier, name and purpose.",
    )
    subparsers.add_parser(
        "version",
        help="Print the Web Guard version.",
        description="Print the Web Guard version.",
    )
    return parser


def _build_run_config(
    args: argparse.Namespace,
) -> tuple[Settings, list[str], list[str], Severity | None]:
    """Merge file configuration, CLI options and defaults."""

    overrides = {
        "timeout": args.timeout,
        "delay": args.delay,
        "max_redirects": args.max_redirects,
        "max_body_bytes": args.max_body_bytes,
        "user_agent": args.user_agent,
        "cors_origin": args.cors_origin,
        "verify_tls": False if args.insecure else None,
        "probe_tls": False if args.no_tls_probe else None,
    }
    settings = settings_from_config(args.config, overrides)
    file_include, file_exclude = checks_from_config(args.config)
    include = _split_checks(args.checks) if args.checks is not None else file_include
    exclude = _dedupe(file_exclude + _split_checks(args.exclude_checks))
    overlap = sorted(set(include) & set(exclude))
    if overlap:
        raise ConfigError(
            "Check identifier(s) cannot be both included and excluded: " + ", ".join(overlap) + "."
        )
    if args.fail_on is None:
        fail_on = fail_on_from_config(args.config)
    elif args.fail_on == "none":
        fail_on = None
    else:
        fail_on = Severity.parse(args.fail_on)
    return settings, include, exclude, fail_on


def _split_checks(value: str | None) -> list[str]:
    """Split a comma separated check list and remove duplicates."""

    if not value:
        return []
    return _dedupe([item.strip() for item in value.split(",") if item.strip()])


def _dedupe(values: list[str]) -> list[str]:
    """Preserve order while removing duplicates."""

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _write_outputs(result: ScanResult, args: argparse.Namespace, target) -> list[str]:
    """Render and write the requested report formats, returning display paths."""

    markdown = render_markdown(result)
    json_text = render_json(result)
    destinations = _resolve_outputs(args.output, args.format, target)
    written: list[str] = []
    for report_format, path in destinations:
        content = markdown if report_format == "md" else json_text
        if path is None:
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
            written.append("standard output")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written.append(str(path))
    return written


def _resolve_outputs(
    output: str | None,
    report_format: str,
    target,
) -> list[tuple[str, Path | None]]:
    """Resolve report paths from the requested format and output option."""

    if output == "-":
        if report_format == "both":
            raise ConfigError("Standard output cannot receive both Markdown and JSON reports.")
        return [(report_format, None)]

    if output:
        base = Path(output).expanduser()
        explicit = True
    else:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
        slug = _slug_for_target(target)
        base = Path(f"web-guard-report-{slug}-{stamp}")
        explicit = False

    if report_format == "both":
        if explicit and base.suffix.lower() in {".md", ".markdown", ".json"}:
            base = base.with_suffix("")
        if not explicit:
            return [("md", Path(f"{base}.md")), ("json", Path(f"{base}.json"))]
        return [("md", base.with_suffix(".md")), ("json", base.with_suffix(".json"))]
    if report_format == "json":
        path = base if (explicit and base.suffix) else Path(f"{base}.json")
        return [("json", path)]
    path = base if (explicit and base.suffix) else Path(f"{base}.md")
    return [("md", path)]


def _slug_for_target(target) -> str:
    """Build a filesystem safe slug from a normalised target."""

    base = target.host
    if target.explicit_port:
        base = f"{base}-{target.port}"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-.")
    return slug or "target"


def _print_checks() -> None:
    """Print the check catalogue in a compact aligned table."""

    catalog = check_catalog()
    print(f"Available checks ({len(catalog)}):")
    for check in catalog.values():
        print(f"  {check.id:<12} {check.name}")
        print(f"  {'':<12} {check.description}")


def _print_summary(result: ScanResult, outputs: list[str], no_color: bool = False) -> None:
    """Print a concise human readable summary to the terminal."""

    color = _use_color(no_color)
    counts = result.severity_counts
    print(_style(f"Web Guard {result.tool_version}", "1", color))
    print(f"Target:  {result.final_url}")
    risk_line = f"Score:   {result.score}/100 (grade {result.grade}, {result.risk} risk)"
    print(_style(risk_line, _risk_colour(result), color))
    print(
        "Findings: "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low, {counts['info']} info"
    )
    for output in outputs:
        print(f"Report:  {output}")


def _risk_colour(result: ScanResult) -> str:
    """Return an ANSI colour code for the risk level."""

    if result.highest_severity in {Severity.CRITICAL, Severity.HIGH}:
        return "31"
    if result.highest_severity is Severity.MEDIUM:
        return "33"
    if result.highest_severity is Severity.LOW:
        return "36"
    return "32"


def _use_color(no_color: bool = False) -> bool:
    """Decide whether ANSI colour should be used on standard output."""

    return not no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _style(text: str, code: str, enabled: bool) -> str:
    """Wrap text in an ANSI style when colour is enabled."""

    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def _configure_logging(verbose: bool, quiet: bool) -> None:
    """Configure root logging for CLI use."""

    if quiet and not verbose:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
