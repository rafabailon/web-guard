"""HTTPS availability and TLS configuration checks.

Transport security is the foundation of every other control. This check inspects
the TLS metadata captured by the scanner, reports missing or broken HTTPS, and
flags certificates that are untrusted, expired or close to expiry. Protocol and
cipher weaknesses are detected from the negotiated connection rather than from a
full cipher suite enumeration, keeping the scan polite and fast.
"""

from __future__ import annotations

from .check_base import Check, ScanContext
from .http_client import is_weak_cipher
from .models import Finding, Severity, TlsInfo

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TransportCheck(Check):
    """Evaluate HTTPS enforcement and the observed TLS connection."""

    id = "transport"
    name = "HTTPS and TLS"
    description = "Checks HTTPS enforcement, certificate trust and lifetime, protocol and cipher strength."
    order = 10

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        final_is_https = context.final_url.startswith("https://")
        target_is_https = context.target.url.startswith("https://")

        if target_is_https and not final_is_https:
            findings.append(self._downgrade(context))
        elif not final_is_https:
            findings.append(self._cleartext(context))

        if final_is_https:
            findings.extend(self._tls(context.detection.tls))
        return findings

    def _cleartext(self, context: ScanContext) -> Finding:
        """Report an HTTP-only target or a missing HTTPS redirect."""

        tls = context.detection.tls
        if tls is not None and tls.available:
            return Finding(
                id="transport.https.redirect_missing",
                check=self.id,
                title="HTTPS is available but the HTTP request is not redirected",
                severity=Severity.HIGH,
                category="Transport security",
                description=(
                    "The site responds to the HTTPS endpoint, but the audited HTTP request was answered without a "
                    "redirect to HTTPS. Users who type the host name or follow an HTTP link therefore transmit their "
                    "first request, cookies and any credentials in clear text."
                ),
                evidence=f"Final URL: {context.final_url}; HTTPS endpoint: {tls.summary}",
                remediation=(
                    "Redirect every HTTP request to the equivalent HTTPS URL with a 301 or 308 response before any "
                    "application content is returned, and enable HSTS."
                ),
                references=(
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ),
                cwe="CWE-319",
            )
        return Finding(
            id="transport.https.missing",
            check=self.id,
            title="The site is served over plain HTTP",
            severity=Severity.HIGH,
            category="Transport security",
            description=(
                "The audited page is delivered over unencrypted HTTP. Traffic can be read and modified by anyone on "
                "the network path, and credentials or session cookies sent by the page are exposed."
            ),
            evidence=f"Final URL: {context.final_url}. No usable HTTPS endpoint was observed.",
            remediation=(
                "Obtain a trusted certificate, serve the site over HTTPS, redirect all HTTP traffic permanently and "
                "add a long lived HSTS policy once HTTPS is stable."
            ),
            references=(
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ),
            cwe="CWE-319",
        )

    def _downgrade(self, context: ScanContext) -> Finding:
        """Report an HTTPS request that ends on an HTTP response."""

        return Finding(
            id="transport.https.downgrade",
            check=self.id,
            title="HTTPS requests are redirected to plain HTTP",
            severity=Severity.HIGH,
            category="Transport security",
            description=(
                "The scan started with HTTPS but the final response was delivered over HTTP. This actively downgrades "
                "a protected connection and is worse than a site that simply lacks HTTPS because users are led to "
                "believe the connection is secure."
            ),
            evidence=f"Requested: {context.target.url}; final: {context.final_url}",
            remediation="Remove the downgrade redirect and terminate TLS at the edge or origin. Never redirect HTTPS to HTTP.",
            references=(
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ),
            cwe="CWE-319",
        )

    def _tls(self, tls: TlsInfo | None) -> list[Finding]:
        """Inspect certificate and negotiated protocol metadata."""

        if tls is None or not tls.available:
            detail = tls.error if tls and tls.error else "No TLS metadata was captured."
            return [
                Finding(
                    id="transport.tls.inspection_unavailable",
                    check=self.id,
                    title="TLS parameters could not be inspected",
                    severity=Severity.MEDIUM,
                    category="Transport security",
                    description=(
                        "The page was delivered over HTTPS but the scanner could not inspect the negotiated protocol, "
                        "cipher or certificate. The transport may still be sound, but its configuration remains unverified."
                    ),
                    evidence=detail,
                    remediation="Confirm TLS termination and certificate configuration manually, then re-run the audit.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-295",
                )
            ]

        findings: list[Finding] = []
        if not tls.verified:
            findings.append(
                Finding(
                    id="transport.tls.untrusted",
                    check=self.id,
                    title="TLS certificate is not trusted",
                    severity=Severity.HIGH,
                    category="Transport security",
                    description=(
                        "The certificate chain could not be verified by the system trust store. Browsers will warn "
                        "users or block the connection, and clients that ignore the warning lose protection against "
                        "man-in-the-middle attacks."
                    ),
                    evidence=(
                        f"Verification error: {tls.error or 'unknown'}; subject: {tls.subject or 'unknown'}; "
                        f"expires: {tls.not_after or 'unknown'}"
                    ),
                    remediation=(
                        "Install a certificate issued by a publicly trusted authority, serve the complete intermediate "
                        "chain and make sure the host name matches the certificate subject or SAN."
                    ),
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-295",
                )
            )

        if tls.verified and tls.days_remaining is not None:
            if tls.days_remaining < 0:
                findings.append(
                    Finding(
                        id="transport.tls.expired",
                        check=self.id,
                        title="TLS certificate has expired",
                        severity=Severity.HIGH,
                        category="Transport security",
                        description=(
                            "The certificate validity period has ended. Clients that enforce validation will refuse the "
                            "connection, and users may be trained to bypass warnings."
                        ),
                        evidence=f"Certificate expired on {tls.not_after} ({abs(tls.days_remaining)} days ago).",
                        remediation="Renew the certificate and automate renewal and expiry monitoring.",
                        references=(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                        ),
                        cwe="CWE-298",
                    )
                )
            elif tls.days_remaining <= 30:
                severity = Severity.MEDIUM if tls.days_remaining <= 7 else Severity.LOW
                findings.append(
                    Finding(
                        id="transport.tls.expiring",
                        check=self.id,
                        title="TLS certificate expires soon",
                        severity=severity,
                        category="Transport security",
                        description=(
                            "The certificate has little remaining validity. Without automated renewal the site will "
                            "start producing browser trust errors when the certificate expires."
                        ),
                        evidence=f"Certificate expires on {tls.not_after}, {tls.days_remaining} days from the scan.",
                        remediation="Renew the certificate and automate renewal with monitoring for failures.",
                        references=(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                        ),
                        cwe="CWE-298",
                    )
                )

        if tls.version and tls.version in _WEAK_PROTOCOLS:
            findings.append(
                Finding(
                    id="transport.tls.weak_protocol",
                    check=self.id,
                    title="Obsolete TLS protocol version is enabled",
                    severity=Severity.HIGH,
                    category="Transport security",
                    description=(
                        "The negotiated protocol is no longer considered secure. TLS 1.0 and 1.1 have known design "
                        "weaknesses and are deprecated by browsers and standards bodies."
                    ),
                    evidence=f"Negotiated protocol: {tls.version}; cipher: {tls.cipher or 'unknown'}",
                    remediation="Disable SSLv3, TLS 1.0 and TLS 1.1. Allow TLS 1.2 with strong suites and prefer TLS 1.3.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-326",
                )
            )
        if tls.cipher and is_weak_cipher(tls.cipher):
            findings.append(
                Finding(
                    id="transport.tls.weak_cipher",
                    check=self.id,
                    title="TLS connection uses a weak cipher",
                    severity=Severity.HIGH,
                    category="Transport security",
                    description=(
                        "The negotiated cipher contains a component with known weaknesses, such as RC4, 3DES, a NULL "
                        "encryption mode or a deprecated hash. Such suites can undermine the confidentiality or "
                        "integrity of the connection."
                    ),
                    evidence=f"Cipher: {tls.cipher}; protocol: {tls.version or 'unknown'}",
                    remediation="Restrict the TLS configuration to modern AEAD suites and remove export, NULL, RC4 and 3DES ciphers.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                    ),
                    cwe="CWE-327",
                )
            )
        return findings
