"""Information disclosure checks.

Version banners, framework debug output and directory listings make targeted
attacks easier even when they are not exploitable on their own. The check also
fetches a deliberately nonexistent path to look for verbose framework error
pages. It records which pattern matched, never the surrounding content, so the
report can be shared without reproducing sensitive output.
"""

from __future__ import annotations

import re

from .check_base import Check, ScanContext
from .models import Finding, Severity
from .utils import clean_text

_VERSION_PATTERN = re.compile(r"\d+\.\d+")
_DIRECTORY_LISTING = re.compile(r"<title>\s*Index of\s*/", re.IGNORECASE)

_VERBOSE_PATTERNS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "Python traceback", Severity.MEDIUM),
    (re.compile(r"\bat [\w.$]+\([^)]*\.java:\d+\)"), "Java stack trace", Severity.MEDIUM),
    (
        re.compile(r"System\.(?:NullReferenceException|InvalidOperationException|ArgumentException)", re.IGNORECASE),
        "ASP.NET exception details",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|PostgreSQL.*ERROR", re.IGNORECASE),
        "database error message",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"You're seeing this error because you have DEBUG = True", re.IGNORECASE),
        "Django debug page",
        Severity.MEDIUM,
    ),
    (re.compile(r"Whoops, looks like something went wrong", re.IGNORECASE), "Laravel error page", Severity.MEDIUM),
    (re.compile(r"Symfony\\Component\\|Symfony Exception", re.IGNORECASE), "Symfony exception page", Severity.MEDIUM),
    (
        re.compile(r"(?:Fatal error|Parse error|Warning):[^<\n]{0,200}on line \d+", re.IGNORECASE),
        "PHP error with file and line",
        Severity.LOW,
    ),
    (re.compile(r"Whitelabel Error Page", re.IGNORECASE), "Spring Boot default error page", Severity.LOW),
    (re.compile(r"Stack trace:", re.IGNORECASE), "stack trace", Severity.LOW),
)


class DisclosureCheck(Check):
    """Report version banners, debug pages and directory listings."""

    id = "disclosure"
    name = "Information disclosure"
    description = "Checks server banners, framework headers, verbose errors and directory listings."
    order = 60

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._banners(context))
        findings.extend(self._generator(context))
        findings.extend(self._directory_listing(context))
        findings.extend(self._verbose_error(context))
        return findings

    def _banners(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        server = context.response.header("server").strip()
        if server and _VERSION_PATTERN.search(server):
            findings.append(
                Finding(
                    id="disclosure.server_version",
                    check=self.id,
                    title="Server banner discloses software version",
                    severity=Severity.LOW,
                    category="Information disclosure",
                    description=(
                        "The Server header includes a version number. While not a vulnerability, it tells an attacker "
                        "which software and patch level to target and removes the need for fingerprinting."
                    ),
                    evidence=f"Server: {clean_text(server, 200)}",
                    remediation=(
                        "Return a generic product name or no Server header, and keep the server fully patched. Header "
                        "removal is hardening, not a substitute for updates."
                    ),
                    references=("https://owasp.org/www-project-secure-headers/",),
                    cwe="CWE-200",
                )
            )

        powered_by = context.response.header("x-powered-by").strip()
        if powered_by:
            findings.append(
                Finding(
                    id="disclosure.powered_by",
                    check=self.id,
                    title="X-Powered-By header discloses the application stack",
                    severity=Severity.LOW,
                    category="Information disclosure",
                    description=(
                        "The application reveals its runtime or framework through X-Powered-By. This helps an attacker "
                        "select framework specific payloads and infer the patch level."
                    ),
                    evidence=f"X-Powered-By: {clean_text(powered_by, 200)}",
                    remediation="Disable the header in the application or reverse proxy configuration.",
                    references=("https://owasp.org/www-project-secure-headers/",),
                    cwe="CWE-200",
                )
            )

        for header, label in (
            ("x-aspnet-version", "ASP.NET version"),
            ("x-aspnetmvc-version", "ASP.NET MVC version"),
            ("x-generator", "generator"),
        ):
            value = context.response.header(header).strip()
            if value:
                findings.append(
                    Finding(
                        id=f"disclosure.{header.replace('-', '_')}",
                        check=self.id,
                        title=f"{label.capitalize()} header is exposed",
                        severity=Severity.LOW,
                        category="Information disclosure",
                        description=(
                            "A framework or generator header advertises the technology and often its version. This is "
                            "unnecessary metadata that assists targeted exploitation."
                        ),
                        evidence=f"{header}: {clean_text(value, 200)}",
                        remediation=f"Remove the {header} header from responses.",
                        references=("https://owasp.org/www-project-secure-headers/",),
                        cwe="CWE-200",
                    )
                )

        for header, label in (
            ("x-debug-token", "Symfony debug token"),
            ("x-debug-token-link", "Symfony profiler link"),
        ):
            value = context.response.header(header).strip()
            if value:
                findings.append(
                    Finding(
                        id=f"disclosure.{header.replace('-', '_')}",
                        check=self.id,
                        title=f"{label} is exposed",
                        severity=Severity.MEDIUM,
                        category="Information disclosure",
                        description=(
                            "A debug token indicates that the framework profiler is active in this environment. Profiler "
                            "pages often contain request data, SQL queries, configuration and sometimes secrets."
                        ),
                        evidence=f"{header}: {clean_text(value, 200)}",
                        remediation="Disable the framework profiler and debug mode in every internet facing environment.",
                        references=("https://symfony.com/doc/current/performance.html",),
                        cwe="CWE-215",
                    )
                )
        return findings

    def _generator(self, context: ScanContext) -> list[Finding]:
        if not context.page or not context.page.meta_generator:
            return []
        generator = context.page.meta_generator
        if not _VERSION_PATTERN.search(generator):
            return []
        return [
            Finding(
                id="disclosure.generator_meta",
                check=self.id,
                title="HTML meta generator reveals a software version",
                severity=Severity.INFO,
                category="Information disclosure",
                description=(
                    "The document includes a generator meta tag with a version number. Content management systems often "
                    "add this by default, and it makes version specific attacks easier."
                ),
                evidence=f"meta generator: {clean_text(generator, 200)}",
                remediation="Remove the generator meta tag where the platform allows it.",
                references=("https://owasp.org/www-project-secure-headers/",),
                cwe="CWE-200",
            )
        ]

    def _directory_listing(self, context: ScanContext) -> list[Finding]:
        if context.response.status != 200:
            return []
        title = context.page.title if context.page else ""
        body = context.response.text
        if title.lower().startswith("index of") or _DIRECTORY_LISTING.search(body):
            return [
                Finding(
                    id="disclosure.directory_listing",
                    check=self.id,
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    category="Information disclosure",
                    description=(
                        "The server returns an automatically generated file index. Directory listings reveal file names, "
                        "backups, uploads and administrative paths, and can expose files that are not meant to be public."
                    ),
                    evidence=f"Directory index detected at {context.final_url}.",
                    remediation=(
                        "Disable automatic directory indexes at the web server, deny access to directories without an "
                        "intended index document and keep secrets outside the document root."
                    ),
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    ),
                    cwe="CWE-548",
                )
            ]
        return []

    def _verbose_error(self, context: ScanContext) -> list[Finding]:
        response = context.not_found
        if response is None:
            return []
        body = response.text
        for pattern, label, severity in _VERBOSE_PATTERNS:
            if pattern.search(body):
                return [
                    Finding(
                        id="disclosure.verbose_error",
                        check=self.id,
                        title="Verbose error page discloses implementation details",
                        severity=severity,
                        category="Information disclosure",
                        description=(
                            "A nonexistent path produced a framework or runtime error page containing implementation "
                            "details. Such pages can reveal absolute paths, library versions, database errors and source "
                            "fragments that help an attacker."
                        ),
                        evidence=(
                            f"Request to a nonexistent path returned status {response.status} with a {label} pattern. "
                            "The response body is intentionally omitted from this report."
                        ),
                        remediation=(
                            "Disable debug mode in production, return a generic error page and log technical details "
                            "only on the server. Ensure custom 404 handlers cover every route."
                        ),
                        references=("https://cwe.mitre.org/data/definitions/209.html",),
                        cwe="CWE-209",
                    )
                ]
        return []
