"""Exposure checks for a small set of well-known sensitive files.

The probe list is deliberately short, static and read-only. Web Guard does not
crawl directories or guess backup names. Each response must match a content
signature, and responses identical to a random not-found baseline are discarded,
which prevents single page applications from producing false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin

from .check_base import Check, ScanContext
from .errors import CheckSkipped, RequestError
from .models import Finding, Severity
from .utils import clean_text


@dataclass(frozen=True)
class FileProbe:
    """Definition of one sensitive file probe."""

    id: str
    path: str
    title: str
    severity: Severity
    patterns: tuple[tuple[re.Pattern[bytes], str], ...]
    description: str
    remediation: str
    cwe: str = "CWE-538"


_PROBES: tuple[FileProbe, ...] = (
    FileProbe(
        id="files.dotenv",
        path="/.env",
        title="Environment file is publicly accessible",
        severity=Severity.CRITICAL,
        patterns=((re.compile(rb"(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}="), "environment variable assignment"),),
        description=(
            "A .env file is served by the web server. These files normally contain database credentials, API keys, "
            "application secrets and mail configuration. Exposure usually leads directly to full compromise."
        ),
        remediation=(
            "Block dotfiles at the web server, move secrets outside the document root, rotate every value that may "
            "have been exposed and review access logs for retrieval."
        ),
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.dotenv_backup",
        path="/.env.bak",
        title="Environment backup file is publicly accessible",
        severity=Severity.CRITICAL,
        patterns=((re.compile(rb"(?m)^[A-Za-z_][A-Za-z0-9_]{1,64}="), "environment variable assignment"),),
        description=(
            "A backup copy of the environment file is reachable. Backup files often contain the same secrets as the "
            "live configuration and are frequently forgotten during rotation."
        ),
        remediation=(
            "Remove backup files from the document root, block their extensions and rotate all secrets that were "
            "present in the file."
        ),
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.git_head",
        path="/.git/HEAD",
        title="Git metadata is exposed",
        severity=Severity.HIGH,
        patterns=(
            (re.compile(rb"ref:\s+refs/"), "Git HEAD reference"),
            (re.compile(rb"\A[0-9a-f]{40}\s*\Z"), "detached Git commit hash"),
        ),
        description=(
            "The .git directory is served by the web server. An attacker can often reconstruct source code, commit "
            "history, credentials and internal documentation from the repository objects."
        ),
        remediation=(
            "Deny access to .git and other version control directories at the web server, remove the directory from "
            "the deployment and rotate any secrets found in history."
        ),
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.git_config",
        path="/.git/config",
        title="Git configuration is exposed",
        severity=Severity.HIGH,
        patterns=((re.compile(rb"\[core\]"), "Git configuration section"),),
        description=(
            "The repository configuration is readable. It can reveal remote URLs, deployment paths and sometimes "
            "embedded credentials, and confirms that the full repository may be downloadable."
        ),
        remediation="Block access to .git, remove repository data from the web root and rotate any credentials it contains.",
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.wp_config_backup",
        path="/wp-config.php.bak",
        title="WordPress configuration backup is publicly accessible",
        severity=Severity.CRITICAL,
        patterns=(
            (re.compile(rb"DB_(?:PASSWORD|NAME|USER)"), "WordPress database constants"),
            (re.compile(rb"define\(\s*['\"]DB_"), "WordPress database definition"),
        ),
        description=(
            "A backup of the WordPress configuration is downloadable. It typically contains database credentials and "
            "authentication keys that allow an attacker to take over the site."
        ),
        remediation=(
            "Delete backup files from the web root, deny backup extensions and rotate database and authentication "
            "salts immediately."
        ),
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.backup_sql",
        path="/backup.sql",
        title="Database dump is publicly accessible",
        severity=Severity.CRITICAL,
        patterns=(
            (re.compile(rb"CREATE TABLE", re.IGNORECASE), "SQL table definition"),
            (re.compile(rb"INSERT INTO", re.IGNORECASE), "SQL insert statement"),
        ),
        description=(
            "A SQL dump is served from the web root. It can contain user records, password hashes, tokens and the "
            "complete schema of the application."
        ),
        remediation=(
            "Remove the dump from the web root, store backups outside the document root, restrict access by network "
            "and rotate any credentials or user data involved."
        ),
        cwe="CWE-538",
    ),
    FileProbe(
        id="files.phpinfo",
        path="/phpinfo.php",
        title="PHP information page is exposed",
        severity=Severity.HIGH,
        patterns=(
            (re.compile(rb"PHP Version"), "PHP version output"),
            (re.compile(rb"phpinfo\(\)"), "phpinfo page"),
        ),
        description=(
            "A phpinfo page reveals the PHP build, loaded modules, configuration paths, environment variables and "
            "sometimes credentials. It is a reconnaissance aid and can leak secrets directly."
        ),
        remediation="Delete phpinfo scripts from production and disable functions that expose configuration.",
        cwe="CWE-200",
    ),
    FileProbe(
        id="files.server_status",
        path="/server-status",
        title="Web server status page is exposed",
        severity=Severity.MEDIUM,
        patterns=((re.compile(rb"Apache Server Status"), "Apache status page"),),
        description=(
            "The Apache server status handler is publicly reachable. It discloses active requests, client addresses, "
            "worker state and internal URLs, which helps an attacker time and target requests."
        ),
        remediation="Restrict /server-status to localhost or an administrative network and disable the module where unused.",
        cwe="CWE-200",
    ),
    FileProbe(
        id="files.ds_store",
        path="/.DS_Store",
        title="macOS metadata file is exposed",
        severity=Severity.LOW,
        patterns=((re.compile(rb"Bud1"), "macOS Finder metadata"),),
        description=(
            "A .DS_Store file is downloadable. It lists directory contents and can reveal file names that are not "
            "linked from the site, including backups and staging material."
        ),
        remediation="Block dotfiles at the web server and remove operating system metadata from deployments.",
        cwe="CWE-538",
    ),
)


class SensitiveFilesCheck(Check):
    """Probe a fixed list of common sensitive paths for matched content."""

    id = "files"
    name = "Exposed sensitive files"
    description = "Checks a small set of well-known configuration, repository and backup paths."
    order = 80

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        completed = 0
        for probe in _PROBES:
            url = urljoin(context.final_url, probe.path)
            try:
                response = context.client.request(url)
                completed += 1
            except RequestError:
                continue
            if not 200 <= response.status < 300:
                continue
            if self._is_soft_not_found(context, response):
                continue
            matched_label = self._match(probe, response.body)
            if matched_label is None:
                continue
            findings.append(
                Finding(
                    id=probe.id,
                    check=self.id,
                    title=probe.title,
                    severity=probe.severity,
                    category="Sensitive file exposure",
                    description=probe.description,
                    evidence=(
                        f"{probe.path} returned HTTP {response.status} with Content-Type "
                        f"{clean_text(response.header('content-type') or 'unknown', 100)}; matched {matched_label}. "
                        "The response body is intentionally omitted."
                    ),
                    remediation=probe.remediation,
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    ),
                    cwe=probe.cwe,
                )
            )
        if completed == 0:
            raise CheckSkipped("No sensitive file request could be completed.")
        return findings

    def _is_soft_not_found(self, context: ScanContext, response) -> bool:
        baseline = context.not_found
        if baseline is None or not baseline.body:
            return False
        return (
            response.status == baseline.status
            and response.body == baseline.body
            and response.content_type == baseline.content_type
        )

    def _match(self, probe: FileProbe, body: bytes) -> str | None:
        for pattern, label in probe.patterns:
            if pattern.search(body):
                return label
        return None
