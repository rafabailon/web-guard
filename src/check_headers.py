"""HTTP security header checks.

Headers are cheap to deploy and defend against whole classes of browser side
attacks, yet they are frequently omitted or configured too loosely. This module
checks the headers that have broad, well understood value and analyses the two
policy headers that need semantic inspection: Content-Security-Policy and
Strict-Transport-Security.
"""

from __future__ import annotations

import re

from .check_base import Check, ScanContext
from .models import Finding, Severity

_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_SAFE_REFERRER_VALUES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


class HeaderCheck(Check):
    """Audit common browser security headers and their policy values."""

    id = "headers"
    name = "HTTP security headers"
    description = "Checks HSTS, CSP, clickjacking, MIME sniffing, referrer and isolation headers."
    order = 20

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._hsts(context))
        findings.extend(self._csp(context))
        findings.extend(self._frame_options(context))
        findings.extend(self._content_type_options(context))
        findings.extend(self._referrer_policy(context))
        findings.extend(self._permissions_policy(context))
        findings.extend(self._isolation_headers(context))
        return findings

    def _hsts(self, context: ScanContext) -> list[Finding]:
        if not context.final_url.startswith("https://"):
            return []
        value = context.response.header("strict-transport-security").strip()
        if not value:
            return [
                Finding(
                    id="headers.hsts.missing",
                    check=self.id,
                    title="Strict-Transport-Security header is missing",
                    severity=Severity.MEDIUM,
                    category="Transport security",
                    description=(
                        "The HTTPS response does not instruct browsers to use HTTPS for future requests. "
                        "Without HSTS a user can be downgraded to plain HTTP by an active network attacker, "
                        "and the first request of a session remains interceptable."
                    ),
                    evidence="Strict-Transport-Security is absent from the final HTTPS response.",
                    remediation=(
                        "Send Strict-Transport-Security with a max-age of at least 15552000 seconds once every "
                        "subdomain is HTTPS ready. Add includeSubDomains when appropriate and consider preload "
                        "after confirming the whole domain is committed to HTTPS."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            ]
        match = _HSTS_MAX_AGE.search(value)
        if not match:
            return [
                Finding(
                    id="headers.hsts.invalid",
                    check=self.id,
                    title="Strict-Transport-Security has no valid max-age",
                    severity=Severity.MEDIUM,
                    category="Transport security",
                    description=(
                        "An HSTS header without a valid max-age directive is ignored by browsers, so the "
                        "protection it appears to provide is not active."
                    ),
                    evidence=f"Strict-Transport-Security: {value}",
                    remediation="Include a max-age directive in seconds, for example max-age=31536000; includeSubDomains.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            ]
        max_age = int(match.group(1))
        if max_age == 0:
            return [
                Finding(
                    id="headers.hsts.zero",
                    check=self.id,
                    title="Strict-Transport-Security disables itself with max-age=0",
                    severity=Severity.MEDIUM,
                    category="Transport security",
                    description=(
                        "A zero max-age removes any existing HSTS policy from the browser. It is useful only "
                        "as an intentional rollback and should not be served in normal operation."
                    ),
                    evidence=f"Strict-Transport-Security: {value}",
                    remediation="Use a positive max-age such as 31536000 and remove the zero value from production.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            ]
        if max_age < 15552000:
            return [
                Finding(
                    id="headers.hsts.short",
                    check=self.id,
                    title="Strict-Transport-Security max-age is shorter than six months",
                    severity=Severity.LOW,
                    category="Transport security",
                    description=(
                        "The HSTS lifetime is shorter than the six months recommended for a stable production "
                        "site. A short lifetime leaves more opportunities for a downgrade between visits."
                    ),
                    evidence=f"Strict-Transport-Security: {value}",
                    remediation="Raise max-age to at least 15552000 seconds, preferably 31536000 seconds.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            ]
        return []

    def _csp(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        report_only = context.response.header("content-security-policy-report-only").strip()
        policy = context.response.header("content-security-policy").strip()
        if not policy:
            description = "The response does not define a Content-Security-Policy."
            evidence = "Content-Security-Policy is absent from the final response."
            if report_only:
                description += (
                    " A report-only policy is present, but it does not block any content and therefore does not "
                    "mitigate script injection."
                )
                evidence += " Content-Security-Policy-Report-Only was found instead."
            findings.append(
                Finding(
                    id="headers.csp.missing",
                    check=self.id,
                    title="Content-Security-Policy is missing",
                    severity=Severity.MEDIUM,
                    category="Content security",
                    description=description,
                    evidence=evidence,
                    remediation=(
                        "Deploy an enforcing Content-Security-Policy with a restrictive default-src, an explicit "
                        "script-src and object-src 'none'. Prefer nonces or hashes over unsafe-inline and roll the "
                        "policy out in report-only mode first to measure breakage."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
            return findings

        parsed = _parse_csp(policy)
        effective_scripts = parsed.get("script-src") or parsed.get("default-src") or []
        lowered_scripts = [source.lower().strip("'\"") for source in effective_scripts]

        if "unsafe-inline" in lowered_scripts:
            findings.append(
                Finding(
                    id="headers.csp.unsafe_inline",
                    check=self.id,
                    title="Content-Security-Policy allows unsafe-inline scripts",
                    severity=Severity.MEDIUM,
                    category="Content security",
                    description=(
                        "unsafe-inline permits inline script execution and event handler attributes. If an attacker "
                        "can inject markup, the policy provides little protection against script execution."
                    ),
                    evidence=f"script sources: {' '.join(effective_scripts) or '(empty)'}",
                    remediation=(
                        "Remove unsafe-inline and move inline code to external files or authorise it with a per-response "
                        "nonce or a hash."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
        if "unsafe-eval" in lowered_scripts:
            findings.append(
                Finding(
                    id="headers.csp.unsafe_eval",
                    check=self.id,
                    title="Content-Security-Policy allows unsafe-eval",
                    severity=Severity.MEDIUM,
                    category="Content security",
                    description=(
                        "unsafe-eval enables string to code execution primitives such as eval and Function. "
                        "It weakens the policy against DOM based injection and should be avoided."
                    ),
                    evidence=f"script sources: {' '.join(effective_scripts) or '(empty)'}",
                    remediation="Remove unsafe-eval and replace dynamic code construction with safer APIs.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
        if any(source in {"*", "http:", "https:"} for source in lowered_scripts):
            findings.append(
                Finding(
                    id="headers.csp.wildcard",
                    check=self.id,
                    title="Content-Security-Policy permits scripts from any origin",
                    severity=Severity.HIGH,
                    category="Content security",
                    description=(
                        "The script policy contains a wildcard or a bare scheme source. This allows scripts from "
                        "arbitrary hosts, which defeats the main origin restriction of CSP."
                    ),
                    evidence=f"script sources: {' '.join(effective_scripts) or '(empty)'}",
                    remediation="Replace wildcards and bare schemes with explicit trusted hosts, nonces or hashes.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
        if "default-src" not in parsed:
            findings.append(
                Finding(
                    id="headers.csp.no_default_src",
                    check=self.id,
                    title="Content-Security-Policy has no default-src fallback",
                    severity=Severity.LOW,
                    category="Content security",
                    description=(
                        "Directives without an explicit rule fall back to default-src. Without it, several resource "
                        "types remain unrestricted and the policy is easier to bypass."
                    ),
                    evidence=f"directives: {', '.join(sorted(parsed)) or '(none)'}",
                    remediation="Add a restrictive default-src such as default-src 'self' and override only what is needed.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
        if "object-src" not in parsed:
            findings.append(
                Finding(
                    id="headers.csp.no_object_src",
                    check=self.id,
                    title="Content-Security-Policy does not block plugin content with object-src",
                    severity=Severity.INFO,
                    category="Content security",
                    description=(
                        "object-src controls legacy plugin content such as Flash and Java. Explicitly setting it to "
                        "'none' is a low cost hardening step recommended by most CSP guidance."
                    ),
                    evidence=f"directives: {', '.join(sorted(parsed)) or '(none)'}",
                    remediation="Add object-src 'none' to the policy.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    ),
                    cwe="CWE-693",
                )
            )
        return findings

    def _frame_options(self, context: ScanContext) -> list[Finding]:
        value = context.response.header("x-frame-options").strip()
        policy = context.response.header("content-security-policy").lower()
        has_frame_ancestors = "frame-ancestors" in policy
        if not value:
            if has_frame_ancestors:
                return []
            return [
                Finding(
                    id="headers.xfo.missing",
                    check=self.id,
                    title="Clickjacking protection is missing",
                    severity=Severity.MEDIUM,
                    category="Clickjacking",
                    description=(
                        "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive prevents "
                        "the page from being embedded in another site. An attacker could overlay invisible controls "
                        "and trick a user into clicking them."
                    ),
                    evidence="X-Frame-Options is absent and CSP has no frame-ancestors directive.",
                    remediation=(
                        "Send Content-Security-Policy: frame-ancestors 'self' (or a narrower list) and keep "
                        "X-Frame-Options: DENY or SAMEORIGIN for older browsers."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                    ),
                    cwe="CWE-1021",
                )
            ]
        normalised = value.split(",")[0].strip().upper()
        if normalised not in {"DENY", "SAMEORIGIN"} and not normalised.startswith("ALLOW-FROM"):
            return [
                Finding(
                    id="headers.xfo.invalid",
                    check=self.id,
                    title="X-Frame-Options uses an unrecognised value",
                    severity=Severity.LOW,
                    category="Clickjacking",
                    description=(
                        "Browsers ignore unknown X-Frame-Options values. An invalid directive therefore provides no "
                        "clickjacking protection even though the header appears to be configured."
                    ),
                    evidence=f"X-Frame-Options: {value}",
                    remediation="Use DENY or SAMEORIGIN, or prefer the CSP frame-ancestors directive.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                    ),
                    cwe="CWE-1021",
                )
            ]
        if normalised.startswith("ALLOW-FROM"):
            return [
                Finding(
                    id="headers.xfo.allow_from",
                    check=self.id,
                    title="X-Frame-Options uses the deprecated ALLOW-FROM directive",
                    severity=Severity.LOW,
                    category="Clickjacking",
                    description=(
                        "ALLOW-FROM is not supported by modern browsers, so the intended restriction is not enforced. "
                        "The CSP frame-ancestors directive replaces it."
                    ),
                    evidence=f"X-Frame-Options: {value}",
                    remediation="Replace ALLOW-FROM with Content-Security-Policy: frame-ancestors and a suitable source list.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                    ),
                    cwe="CWE-1021",
                )
            ]
        return []

    def _content_type_options(self, context: ScanContext) -> list[Finding]:
        value = context.response.header("x-content-type-options").strip()
        if value.lower() == "nosniff":
            return []
        return [
            Finding(
                id="headers.xcto.missing" if not value else "headers.xcto.invalid",
                check=self.id,
                title="MIME sniffing protection is missing" if not value else "X-Content-Type-Options is not nosniff",
                severity=Severity.LOW,
                category="Content security",
                description=(
                    "Without X-Content-Type-Options: nosniff some browsers may sniff a response as a different media "
                    "type. This can turn an uploaded text file into executable script in the site origin."
                ),
                evidence=f"X-Content-Type-Options: {value}" if value else "X-Content-Type-Options is absent.",
                remediation="Send X-Content-Type-Options: nosniff on every response and set accurate Content-Type headers.",
                references=("https://owasp.org/www-project-secure-headers/",),
                cwe="CWE-693",
            )
        ]

    def _referrer_policy(self, context: ScanContext) -> list[Finding]:
        value = context.response.header("referrer-policy").strip()
        if not value:
            return [
                Finding(
                    id="headers.referrer.missing",
                    check=self.id,
                    title="Referrer-Policy header is missing",
                    severity=Severity.LOW,
                    category="Privacy",
                    description=(
                        "Without an explicit policy the browser default may send full URLs, including path and query "
                        "data, to other origins. Sensitive identifiers in URLs can leak through the Referer header."
                    ),
                    evidence="Referrer-Policy is absent from the final response.",
                    remediation=(
                        "Send Referrer-Policy: strict-origin-when-cross-origin or a stricter policy such as no-referrer "
                        "where cross-site referrers are not needed."
                    ),
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",),
                    cwe="CWE-200",
                )
            ]
        policy = value.split(",")[0].strip().lower()
        if policy in _SAFE_REFERRER_VALUES:
            return []
        if policy in {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}:
            return [
                Finding(
                    id="headers.referrer.weak",
                    check=self.id,
                    title="Referrer-Policy discloses more URL data than necessary",
                    severity=Severity.LOW,
                    category="Privacy",
                    description=(
                        "The configured policy sends more of the source URL to other origins than is normally needed. "
                        "This can disclose path, query string or internal host information to third parties."
                    ),
                    evidence=f"Referrer-Policy: {value}",
                    remediation="Use strict-origin-when-cross-origin or no-referrer.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",),
                    cwe="CWE-200",
                )
            ]
        return []

    def _permissions_policy(self, context: ScanContext) -> list[Finding]:
        value = context.response.header("permissions-policy").strip()
        if value:
            return []
        return [
            Finding(
                id="headers.permissions.missing",
                check=self.id,
                title="Permissions-Policy header is missing",
                severity=Severity.INFO,
                category="Browser features",
                description=(
                    "Permissions-Policy restricts powerful browser features such as camera, microphone and geolocation. "
                    "Omitting it leaves each feature at the browser default, which may allow embedded content to request it."
                ),
                evidence="Permissions-Policy is absent from the final response.",
                remediation="Declare a minimal Permissions-Policy, for example disabling camera, microphone and geolocation where unused.",
                references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",),
                cwe="CWE-693",
            )
        ]

    def _isolation_headers(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not context.response.header("cross-origin-opener-policy").strip():
            findings.append(
                Finding(
                    id="headers.coop.missing",
                    check=self.id,
                    title="Cross-Origin-Opener-Policy header is missing",
                    severity=Severity.INFO,
                    category="Browser isolation",
                    description=(
                        "COOP isolates the browsing context from cross-origin windows. Without it a hostile opener can "
                        "retain a reference to the page and attempt side-channel or navigation attacks."
                    ),
                    evidence="Cross-Origin-Opener-Policy is absent from the final response.",
                    remediation="Send Cross-Origin-Opener-Policy: same-origin on top level documents.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",),
                    cwe="CWE-346",
                )
            )
        if not context.response.header("cross-origin-resource-policy").strip():
            findings.append(
                Finding(
                    id="headers.corp.missing",
                    check=self.id,
                    title="Cross-Origin-Resource-Policy header is missing",
                    severity=Severity.INFO,
                    category="Browser isolation",
                    description=(
                        "CORP lets a site refuse cross-origin reads of its resources. Without it, other sites may be "
                        "able to embed resources in ways the owner did not intend, particularly alongside COEP."
                    ),
                    evidence="Cross-Origin-Resource-Policy is absent from the final response.",
                    remediation="Send Cross-Origin-Resource-Policy: same-origin or same-site where cross-origin embedding is not required.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",),
                    cwe="CWE-346",
                )
            )
        return findings


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into a directive to source list mapping."""

    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives
