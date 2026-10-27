"""Well-known security metadata checks.

security.txt gives researchers a private channel to report vulnerabilities. Its
absence is not a vulnerability, so it is reported as informational only. The
check is kept separate from sensitive file exposure because the intent and the
remediation are different.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .check_base import Check, ScanContext
from .errors import CheckSkipped, RequestError
from .models import Finding, Severity


class WellKnownCheck(Check):
    """Check for a valid security.txt contact document."""

    id = "wellknown"
    name = "Security contact metadata"
    description = "Checks for a security.txt file with a contact entry."
    order = 90

    def run(self, context: ScanContext) -> list[Finding]:
        url = urljoin(context.final_url, "/.well-known/security.txt")
        try:
            response = context.client.request(url)
        except RequestError as exc:
            raise CheckSkipped(f"security.txt could not be requested: {exc}") from exc
        if response.status == 200:
            text = response.text
            if "contact:" in text.lower():
                return []
            return [
                Finding(
                    id="wellknown.security_txt.invalid",
                    check=self.id,
                    title="security.txt exists but has no Contact field",
                    severity=Severity.INFO,
                    category="Vulnerability disclosure",
                    description=(
                        "A security.txt document is published, but it does not declare a Contact field. Researchers "
                        "therefore have no documented route to report a vulnerability privately."
                    ),
                    evidence=f"{url} returned HTTP 200 without a Contact field.",
                    remediation="Add at least one Contact entry, for example a mailto: or https: URL, and set an Expires date.",
                    references=("https://www.rfc-editor.org/rfc/rfc9116",),
                    cwe="",
                )
            ]
        if response.status in {401, 403}:
            raise CheckSkipped(f"security.txt returned HTTP {response.status}; the resource is protected.")
        return [
            Finding(
                id="wellknown.security_txt.missing",
                check=self.id,
                title="security.txt is not published",
                severity=Severity.INFO,
                category="Vulnerability disclosure",
                description=(
                    "The well-known security.txt location does not provide a contact policy. This is not a technical "
                    "vulnerability, but a clear disclosure channel reduces the chance that a researcher reports a flaw "
                    "publicly or not at all."
                ),
                evidence=f"{url} returned HTTP {response.status}.",
                remediation=(
                    "Publish /.well-known/security.txt with Contact, Expires and preferred language fields, following RFC 9116."
                ),
                references=("https://www.rfc-editor.org/rfc/rfc9116",),
                cwe="",
            )
        ]
