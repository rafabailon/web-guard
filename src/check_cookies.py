"""Cookie attribute checks.

Cookies rarely carry explicit vulnerabilities, but weak attributes turn ordinary
cross-site scripting, network interception or subdomain takeover into session
compromise. The check aggregates findings by attribute so that a site setting
twenty cookies does not produce sixty nearly identical entries. Only cookie
names are recorded; values are never copied into the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .check_base import Check, ScanContext
from .models import Finding, Severity

_SESSION_PATTERN = re.compile(r"(sess|sid|auth|token|jwt|remember|login)", re.IGNORECASE)
_CSRF_PATTERN = re.compile(r"(csrf|xsrf|antiforgery)", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedCookie:
    """Minimal parsed representation of one Set-Cookie header."""

    name: str
    attributes: dict[str, str]

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def http_only(self) -> bool:
        return "httponly" in self.attributes

    @property
    def same_site(self) -> str:
        return self.attributes.get("samesite", "").lower()


def parse_set_cookie(value: str) -> ParsedCookie | None:
    """Parse a Set-Cookie header without retaining its value."""

    parts = [part.strip() for part in value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, separator, attribute_value = part.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        attributes[key] = attribute_value.strip().strip('"') if separator else ""
    return ParsedCookie(name=name, attributes=attributes)


class CookieCheck(Check):
    """Check Secure, HttpOnly, SameSite and cookie name prefix rules."""

    id = "cookies"
    name = "Cookie security"
    description = "Checks cookie flags, SameSite behaviour and __Host-/__Secure- prefix requirements."
    order = 30

    def run(self, context: ScanContext) -> list[Finding]:
        cookies = self._parse_all(context)
        if not cookies:
            return []
        findings: list[Finding] = []
        findings.extend(self._missing_secure(cookies))
        findings.extend(self._missing_http_only(cookies))
        findings.extend(self._missing_same_site(cookies))
        findings.extend(self._same_site_none(cookies))
        findings.extend(self._prefix_rules(cookies))
        return findings

    def _parse_all(self, context: ScanContext) -> list[ParsedCookie]:
        parsed: list[ParsedCookie] = []
        for raw in context.response.cookies:
            cookie = parse_set_cookie(raw)
            if cookie is not None:
                parsed.append(cookie)
        return parsed

    def _missing_secure(self, cookies: list[ParsedCookie]) -> list[Finding]:
        affected = [cookie.name for cookie in cookies if not cookie.secure]
        if not affected:
            return []
        session_like = any(_is_session_cookie(name) for name in affected)
        return [
            Finding(
                id="cookies.secure.missing",
                check=self.id,
                title="Cookies are missing the Secure attribute",
                severity=Severity.HIGH if session_like else Severity.MEDIUM,
                category="Session management",
                description=(
                    "A cookie without the Secure attribute can be sent over an unencrypted HTTP connection. If the "
                    "site has any HTTP endpoint, or an attacker can inject a plain HTTP request, the cookie can be "
                    "captured in transit."
                ),
                evidence=f"Cookies without Secure: {', '.join(affected)}",
                remediation="Set the Secure attribute on every cookie and serve the whole site over HTTPS.",
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ),
                cwe="CWE-614",
            )
        ]

    def _missing_http_only(self, cookies: list[ParsedCookie]) -> list[Finding]:
        affected = [
            cookie.name
            for cookie in cookies
            if not cookie.http_only and not _CSRF_PATTERN.search(cookie.name)
        ]
        if not affected:
            return []
        session_like = any(_is_session_cookie(name) for name in affected)
        return [
            Finding(
                id="cookies.httponly.missing",
                check=self.id,
                title="Cookies are readable from JavaScript",
                severity=Severity.HIGH if session_like else Severity.LOW,
                category="Session management",
                description=(
                    "Cookies without HttpOnly can be read by scripts running in the origin. A single cross-site "
                    "scripting flaw then becomes full session theft rather than a limited injection."
                ),
                evidence=f"Cookies without HttpOnly: {', '.join(affected)}",
                remediation=(
                    "Set HttpOnly on session and authentication cookies. Cookies that JavaScript legitimately needs, "
                    "such as CSRF tokens, can remain readable but should carry a narrow scope."
                ),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ),
                cwe="CWE-1004",
            )
        ]

    def _missing_same_site(self, cookies: list[ParsedCookie]) -> list[Finding]:
        affected = [cookie.name for cookie in cookies if not cookie.same_site]
        if not affected:
            return []
        session_like = any(_is_session_cookie(name) for name in affected)
        return [
            Finding(
                id="cookies.samesite.missing",
                check=self.id,
                title="Cookies do not declare a SameSite policy",
                severity=Severity.MEDIUM if session_like else Severity.LOW,
                category="Session management",
                description=(
                    "A cookie without SameSite relies on browser defaults and may be attached to cross-site requests. "
                    "This increases exposure to cross-site request forgery and cross-site information leaks."
                ),
                evidence=f"Cookies without SameSite: {', '.join(affected)}",
                remediation=(
                    "Set SameSite=Lax on session cookies and use SameSite=Strict for sensitive actions. Use "
                    "SameSite=None only when cross-site delivery is required and always combine it with Secure."
                ),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                ),
                cwe="CWE-1275",
            )
        ]

    def _same_site_none(self, cookies: list[ParsedCookie]) -> list[Finding]:
        affected = [cookie.name for cookie in cookies if cookie.same_site == "none" and not cookie.secure]
        if not affected:
            return []
        return [
            Finding(
                id="cookies.samesite.none_without_secure",
                check=self.id,
                title="SameSite=None cookies are missing Secure",
                severity=Severity.MEDIUM,
                category="Session management",
                description=(
                    "Browsers reject SameSite=None cookies unless they also carry Secure. The intended cross-site "
                    "behaviour will not work, or older clients may accept the cookie and send it over HTTP."
                ),
                evidence=f"Cookies with SameSite=None and no Secure: {', '.join(affected)}",
                remediation="Add Secure to every SameSite=None cookie and serve only over HTTPS.",
                references=(
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                ),
                cwe="CWE-1275",
            )
        ]

    def _prefix_rules(self, cookies: list[ParsedCookie]) -> list[Finding]:
        host_violations: list[str] = []
        secure_violations: list[str] = []
        for cookie in cookies:
            if cookie.name.startswith("__Host-"):
                if not cookie.secure or cookie.attributes.get("path") != "/" or "domain" in cookie.attributes:
                    host_violations.append(cookie.name)
            elif cookie.name.startswith("__Secure-") and not cookie.secure:
                secure_violations.append(cookie.name)
        findings: list[Finding] = []
        if host_violations:
            findings.append(
                Finding(
                    id="cookies.prefix.host",
                    check=self.id,
                    title="__Host- cookie prefix requirements are not met",
                    severity=Severity.HIGH,
                    category="Session management",
                    description=(
                        "A __Host- cookie must be Secure, have Path=/ and omit the Domain attribute. Browsers reject "
                        "cookies that violate these rules, so the application may silently lose session state. A cookie "
                        "that is accepted despite a weaker configuration would also be exposed across subdomains."
                    ),
                    evidence=f"Invalid __Host- cookies: {', '.join(host_violations)}",
                    remediation="Set Secure, Path=/ and no Domain attribute on every __Host- cookie.",
                    references=(
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes",
                    ),
                    cwe="CWE-614",
                )
            )
        if secure_violations:
            findings.append(
                Finding(
                    id="cookies.prefix.secure",
                    check=self.id,
                    title="__Secure- cookie prefix requirements are not met",
                    severity=Severity.HIGH,
                    category="Session management",
                    description=(
                        "The __Secure- prefix is only honoured when the cookie also has the Secure attribute. Without "
                        "it the browser rejects the cookie, which can break authentication."
                    ),
                    evidence=f"Invalid __Secure- cookies: {', '.join(secure_violations)}",
                    remediation="Add the Secure attribute to every __Secure- cookie.",
                    references=(
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes",
                    ),
                    cwe="CWE-614",
                )
            )
        return findings


def _is_session_cookie(name: str) -> bool:
    """Heuristically decide whether a cookie name looks session related."""

    if _CSRF_PATTERN.search(name):
        return False
    return bool(_SESSION_PATTERN.search(name))
