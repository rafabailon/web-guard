"""HTTP method exposure checks.

The check uses OPTIONS and TRACE, both safe and idempotent, to discover whether
the server advertises dangerous verbs or still supports the legacy TRACE method.
TRACE is reported only when the server echoes a unique marker, which avoids
false positives from generic 200 responses.
"""

from __future__ import annotations

import secrets

from .check_base import Check, ScanContext
from .errors import CheckSkipped, RequestError
from .models import Finding, Severity

_UNSAFE_METHODS = ("PUT", "DELETE", "PATCH", "CONNECT")


class MethodCheck(Check):
    """Inspect allowed methods and test the TRACE request echo."""

    id = "methods"
    name = "HTTP methods"
    description = "Checks OPTIONS advertisements and whether TRACE reflects request data."
    order = 50

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        failures = 0
        allow_header = ""

        try:
            options_response = context.client.request(context.final_url, method="OPTIONS")
            allow_header = options_response.header("allow").strip()
            if allow_header:
                offered = {
                    token.strip().upper()
                    for token in allow_header.replace(",", " ").split()
                    if token.strip()
                }
                advertised_unsafe = sorted(offered.intersection(_UNSAFE_METHODS))
                if advertised_unsafe:
                    findings.append(
                        Finding(
                            id="methods.unsafe_advertised",
                            check=self.id,
                            title="The server advertises state-changing HTTP methods",
                            severity=Severity.INFO,
                            category="HTTP configuration",
                            description=(
                                "OPTIONS lists methods that can modify state. This is not a vulnerability by itself, "
                                "and the methods may require authentication, but public write verbs on a page that does "
                                "not need them increase attack surface."
                            ),
                            evidence=f"Allow: {allow_header}",
                            remediation=(
                                "Disable unnecessary methods at the reverse proxy or framework level and confirm that "
                                "every write endpoint enforces authorization and CSRF protection."
                            ),
                            references=("https://owasp.org/www-project-web-security-testing-guide/",),
                            cwe="CWE-749",
                        )
                    )
        except RequestError:
            failures += 1

        marker = f"webguard-{secrets.token_hex(8)}"
        try:
            trace_response = context.client.request(
                context.final_url,
                method="TRACE",
                headers={"X-WebGuard-Trace": marker},
            )
            body = trace_response.text
            if trace_response.status == 200 and marker in body:
                findings.append(
                    Finding(
                        id="methods.trace_enabled",
                        check=self.id,
                        title="HTTP TRACE is enabled and reflects request data",
                        severity=Severity.HIGH,
                        category="HTTP configuration",
                        description=(
                            "The server answers TRACE by echoing the request, including headers. This enables Cross-Site "
                            "Tracing, which can be combined with browser bugs or legacy clients to read HttpOnly cookies "
                            "and authentication headers. Modern browsers no longer send TRACE, but the service remains "
                            "unnecessarily exposed."
                        ),
                        evidence=(
                            f"TRACE returned {trace_response.status} and echoed the unique marker "
                            f"X-WebGuard-Trace: {marker}."
                        ),
                        remediation="Disable the TRACE method at the web server or reverse proxy and return 405 Method Not Allowed.",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                        ),
                        cwe="CWE-749",
                    )
                )
        except RequestError:
            failures += 1

        if failures == 2:
            raise CheckSkipped("OPTIONS and TRACE requests both failed; method exposure could not be evaluated.")
        return findings
