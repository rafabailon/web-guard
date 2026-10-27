"""Cross-Origin Resource Sharing policy checks.

The scanner sends a harmless Origin header and inspects the response. A reflected
origin combined with credentials is the dangerous case because any site can read
authenticated responses from the target. Wildcard policies are reported at a low
level because they are sometimes intentional for public APIs.
"""

from __future__ import annotations

from .check_base import Check, ScanContext
from .errors import CheckSkipped, RequestError
from .models import Finding, Severity


class CorsCheck(Check):
    """Inspect Access-Control-Allow-* response headers for unsafe policies."""

    id = "cors"
    name = "CORS policy"
    description = "Checks for reflected origins, wildcards and credential combinations."
    order = 40

    def run(self, context: ScanContext) -> list[Finding]:
        try:
            response = context.client.request(
                context.final_url,
                method="GET",
                headers={"Origin": context.settings.cors_origin},
            )
        except RequestError as exc:
            raise CheckSkipped(f"CORS probe could not be completed: {exc}") from exc

        allow_origin = response.header("access-control-allow-origin").strip()
        if not allow_origin:
            return []
        allow_credentials = response.header("access-control-allow-credentials").strip().lower() == "true"
        origin_sent = context.settings.cors_origin

        if "," in allow_origin:
            return [
                Finding(
                    id="cors.invalid_origin_list",
                    check=self.id,
                    title="Access-Control-Allow-Origin contains multiple origins",
                    severity=Severity.LOW,
                    category="Cross-origin policy",
                    description=(
                        "The specification permits exactly one origin value. A comma separated list will be rejected by "
                        "browsers, and the presence of a list suggests the policy is generated from user controlled input."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                    remediation="Return a single origin that exactly matches an allow-list entry, or omit the header.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",),
                    cwe="CWE-942",
                )
            ]

        if allow_origin.lower() == origin_sent.lower():
            severity = Severity.HIGH if allow_credentials else Severity.MEDIUM
            return [
                Finding(
                    id="cors.reflected_credentials" if allow_credentials else "cors.reflected_origin",
                    check=self.id,
                    title=(
                        "CORS reflects an arbitrary origin with credentials"
                        if allow_credentials
                        else "CORS reflects an arbitrary origin"
                    ),
                    severity=severity,
                    category="Cross-origin policy",
                    description=(
                        "The response echoes whatever Origin the client sends. "
                        + (
                            "Because credentials are also allowed, any website can read authenticated responses from "
                            "the target on behalf of a signed-in user. This is a serious data exposure."
                            if allow_credentials
                            else "Any website can read responses that the browser is allowed to share. If the endpoint "
                            "returns private data or relies on network level authentication, this is a data exposure."
                        )
                    ),
                    evidence=(
                        f"Origin sent: {origin_sent}; Access-Control-Allow-Origin: {allow_origin}; "
                        f"Access-Control-Allow-Credentials: {str(allow_credentials).lower()}"
                    ),
                    remediation=(
                        "Validate Origin against a fixed allow-list and return only a known value. Never reflect origin "
                        "with Access-Control-Allow-Credentials: true. Do not rely on authentication alone for CORS safety."
                    ),
                    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",),
                    cwe="CWE-942",
                )
            ]

        if allow_origin == "null":
            return [
                Finding(
                    id="cors.null_origin",
                    check=self.id,
                    title="CORS accepts the null origin",
                    severity=Severity.HIGH if allow_credentials else Severity.MEDIUM,
                    category="Cross-origin policy",
                    description=(
                        "The null origin is produced by sandboxed frames, data URLs and some local files. Accepting it "
                        "allows attacker controlled contexts to read responses and is almost never intentional."
                    ),
                    evidence=f"Access-Control-Allow-Origin: null; credentials: {str(allow_credentials).lower()}",
                    remediation="Remove null from the allow-list. Match only explicit HTTPS origins that you control.",
                    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",),
                    cwe="CWE-942",
                )
            ]

        if allow_origin == "*":
            if allow_credentials:
                return [
                    Finding(
                        id="cors.wildcard_credentials",
                        check=self.id,
                        title="CORS combines a wildcard origin with credentials",
                        severity=Severity.MEDIUM,
                        category="Cross-origin policy",
                        description=(
                            "Browsers reject a wildcard origin when credentials are enabled, so the policy is invalid and "
                            "breaks legitimate cross-origin requests. The combination usually indicates a misunderstood "
                            "CORS implementation and may be corrected unsafely later."
                        ),
                        evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                        remediation="Use an explicit allow-list instead of combining a wildcard with credentials.",
                        references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",),
                        cwe="CWE-942",
                    )
                ]
            return [
                Finding(
                    id="cors.wildcard",
                    check=self.id,
                    title="CORS allows any origin",
                    severity=Severity.LOW,
                    category="Cross-origin policy",
                    description=(
                        "Any website can read responses from this endpoint without credentials. This is appropriate for "
                        "genuinely public data but exposes private or internal data if the endpoint does not enforce its "
                        "own authorization."
                    ),
                    evidence=f"Access-Control-Allow-Origin: * (request Origin: {origin_sent})",
                    remediation=(
                        "Keep the wildcard only for public, non-sensitive resources. Restrict private endpoints to an "
                        "explicit allow-list."
                    ),
                    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",),
                    cwe="CWE-942",
                )
            ]
        return []
