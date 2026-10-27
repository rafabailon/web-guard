"""Content level checks for mixed content, forms and leaked secrets.

These checks reason about the delivered HTML rather than response headers. They
cover three common classes of mistake: active resources loaded over HTTP on an
HTTPS page, credential forms that are sent insecurely or without CSRF
protection, and high confidence secret patterns embedded in the document. Secret
values are never copied into findings; only the pattern class is reported.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .check_base import Check, ScanContext
from .html import Form, has_blank_link_protection
from .models import Finding, Severity
from .utils import clean_text, is_http_url, redact_url

_ACTIVE_RESOURCE_KINDS = {"script", "stylesheet", "iframe", "object"}
_NAMESPACE_HOSTS = {"www.w3.org", "schemas.xmlsoap.org", "xmlns.com", "schemas.openxmlformats.org"}
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")


class ContentCheck(Check):
    """Inspect the main HTML document for content level weaknesses."""

    id = "content"
    name = "Content and forms"
    description = "Checks mixed content, credential forms, reverse tabnabbing and embedded secrets."
    order = 70

    def run(self, context: ScanContext) -> list[Finding]:
        if context.page is None:
            return []
        findings: list[Finding] = []
        findings.extend(self._mixed_content(context))
        findings.extend(self._forms(context))
        findings.extend(self._blank_links(context))
        findings.extend(self._secrets(context))
        return findings

    def _mixed_content(self, context: ScanContext) -> list[Finding]:
        if not context.final_url.startswith("https://"):
            return []
        if context.page is None:
            return []
        active: list[str] = []
        passive: list[str] = []
        for resource in context.page.resources:
            resolved = context.absolute_url(resource.url)
            if not is_http_url(resolved):
                continue
            host = (urlsplit(resolved).hostname or "").lower()
            if host in _NAMESPACE_HOSTS or host.endswith(".w3.org"):
                continue
            label = f"{resource.tag}[{resource.attribute}]={redact_url(resolved, 200)}"
            if resource.kind in _ACTIVE_RESOURCE_KINDS:
                active.append(label)
            else:
                passive.append(label)

        findings: list[Finding] = []
        if active:
            findings.append(
                Finding(
                    id="content.mixed.active",
                    check=self.id,
                    title="HTTPS page loads active content over HTTP",
                    severity=Severity.HIGH,
                    category="Content security",
                    description=(
                        "Scripts, stylesheets or frames are loaded from plain HTTP on an HTTPS page. Modern browsers "
                        "block or upgrade much of this content, which breaks the page, and any request that is allowed "
                        "can be modified in transit to inject code into the secure origin."
                    ),
                    evidence="Active mixed content references: " + "; ".join(active[:8]),
                    remediation=(
                        "Load every active resource over HTTPS, preferably with a relative URL so the page scheme is "
                        "inherited, and add upgrade-insecure-requests to the CSP during migration."
                    ),
                    references=("https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",),
                    cwe="CWE-311",
                )
            )
        if passive:
            findings.append(
                Finding(
                    id="content.mixed.passive",
                    check=self.id,
                    title="HTTPS page loads passive content over HTTP",
                    severity=Severity.LOW,
                    category="Content security",
                    description=(
                        "Images or media are fetched over plain HTTP on an HTTPS page. The page still works, but the "
                        "content can be replaced in transit and its availability leaks to a network observer."
                    ),
                    evidence="Passive mixed content references: " + "; ".join(passive[:8]),
                    remediation="Serve images and media over HTTPS and enable upgrade-insecure-requests where possible.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",),
                    cwe="CWE-311",
                )
            )
        return findings

    def _forms(self, context: ScanContext) -> list[Finding]:
        if context.page is None:
            return []
        findings: list[Finding] = []
        insecure_actions: list[str] = []
        javascript_actions: list[str] = []
        password_forms: list[Form] = []
        get_forms: list[Form] = []
        missing_csrf: list[Form] = []

        for form in context.page.password_forms:
            password_forms.append(form)
            action = form.action.strip()
            if action.lower().startswith(("javascript:", "data:")):
                javascript_actions.append(form.display_name)
                continue
            resolved = context.absolute_url(action) if action else context.final_url
            if context.final_url.startswith("https://") and resolved.startswith("http://"):
                insecure_actions.append(f"{clean_text(form.display_name, 100)} -> {redact_url(resolved, 200)}")
            if form.method == "get":
                get_forms.append(form)
            elif form.method == "post" and not form.has_csrf_token:
                missing_csrf.append(form)

        if insecure_actions:
            findings.append(
                Finding(
                    id="content.forms.insecure_action",
                    check=self.id,
                    title="Login form submits credentials over plain HTTP",
                    severity=Severity.HIGH,
                    category="Credential protection",
                    description=(
                        "A password form on an HTTPS page posts to an HTTP URL. The credentials leave the protected "
                        "page and travel in clear text, where they can be captured or altered by a network attacker."
                    ),
                    evidence="Insecure form actions: " + "; ".join(insecure_actions[:8]),
                    remediation="Point every credential form at an HTTPS URL and force HTTPS across the whole authentication flow.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            )
        if javascript_actions:
            findings.append(
                Finding(
                    id="content.forms.javascript_action",
                    check=self.id,
                    title="Form action uses a script or data URL",
                    severity=Severity.MEDIUM,
                    category="Content security",
                    description=(
                        "A form action is a javascript: or data: URL. This pattern bypasses normal navigation and can be "
                        "used to execute attacker controlled code if the action is ever influenced by input."
                    ),
                    evidence="Forms with script actions: " + ", ".join(javascript_actions[:8]),
                    remediation="Submit to a normal HTTPS endpoint and handle validation in server side code.",
                    references=("https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form",),
                    cwe="CWE-79",
                )
            )
        if context.final_url.startswith("http://") and password_forms:
            findings.append(
                Finding(
                    id="content.forms.password_http",
                    check=self.id,
                    title="Password form is served over plain HTTP",
                    severity=Severity.HIGH,
                    category="Credential protection",
                    description=(
                        "The page itself is delivered over HTTP and contains a password field. Every credential entered "
                        "into this form is exposed to the network, regardless of where the form submits."
                    ),
                    evidence=f"{len(password_forms)} password form(s) detected on {context.final_url}.",
                    remediation="Serve the login page and all authenticated pages over HTTPS with HSTS enabled.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ),
                    cwe="CWE-319",
                )
            )
        if get_forms:
            findings.append(
                Finding(
                    id="content.forms.password_get",
                    check=self.id,
                    title="Password form uses the GET method",
                    severity=Severity.MEDIUM,
                    category="Credential protection",
                    description=(
                        "A form containing a password submits with GET. The credentials become part of the URL, which is "
                        "stored in browser history, proxy logs, server access logs and Referer headers."
                    ),
                    evidence="Forms using GET with a password field: " + ", ".join(form.display_name for form in get_forms[:8]),
                    remediation="Submit credential forms with POST over HTTPS and avoid putting secrets in URLs.",
                    references=(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ),
                    cwe="CWE-598",
                )
            )
        if missing_csrf:
            findings.append(
                Finding(
                    id="content.forms.csrf_token_missing",
                    check=self.id,
                    title="Password form has no visible anti-CSRF token",
                    severity=Severity.LOW,
                    category="Cross-site request forgery",
                    description=(
                        "A password form posts without a hidden field whose name resembles a CSRF token. The heuristic "
                        "can produce false positives because frameworks sometimes protect requests through headers, "
                        "SameSite cookies or double submit schemes, so confirm the server side behaviour before acting."
                    ),
                    evidence="Forms without a recognised token field: " + ", ".join(form.display_name for form in missing_csrf[:8]),
                    remediation=(
                        "Protect state-changing forms with a server validated anti-CSRF token, SameSite cookies and an "
                        "Origin or Referer check."
                    ),
                    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",),
                    cwe="CWE-352",
                )
            )
        return findings

    def _blank_links(self, context: ScanContext) -> list[Finding]:
        if context.page is None:
            return []
        unprotected = [
            link for link in context.page.blank_links if not has_blank_link_protection(link)
        ]
        if not unprotected:
            return []
        examples = ", ".join(redact_url(link.href, 120) if link.href else "(empty)" for link in unprotected[:5])
        return [
            Finding(
                id="content.links.noopener",
                check=self.id,
                title="Links opening a new tab do not set rel=noopener",
                severity=Severity.LOW,
                category="Content security",
                description=(
                    "Anchors with target=_blank omit noopener or noreferrer. Older browsers expose window.opener to the "
                    "new page, which can redirect the original tab. Most current browsers apply noopener by default, but "
                    "explicit attributes remain the portable and auditable choice."
                ),
                evidence=f"{len(unprotected)} link(s) without protection, for example: {examples}",
                remediation="Add rel=\"noopener noreferrer\" to every anchor that uses target=_blank.",
                references=("https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener",),
                cwe="CWE-1022",
            )
        ]

    def _secrets(self, context: ScanContext) -> list[Finding]:
        text = context.response.text
        findings: list[Finding] = []
        if _PRIVATE_KEY.search(text):
            findings.append(
                Finding(
                    id="content.secrets.private_key",
                    check=self.id,
                    title="A private key appears to be embedded in the page",
                    severity=Severity.CRITICAL,
                    category="Sensitive data exposure",
                    description=(
                        "The response contains a PEM private key header. A private key delivered to a browser must be "
                        "treated as compromised and can be used to impersonate the service or decrypt captured traffic."
                    ),
                    evidence="A private key header was detected in the HTML response. The value is redacted.",
                    remediation=(
                        "Remove the key from the document immediately, rotate it, and move signing or decryption to the "
                        "server. Review caches, build artefacts and version history for copies."
                    ),
                    references=("https://cwe.mitre.org/data/definitions/798.html",),
                    cwe="CWE-798",
                )
            )
        if _AWS_ACCESS_KEY.search(text):
            findings.append(
                Finding(
                    id="content.secrets.aws_key",
                    check=self.id,
                    title="An AWS access key pattern appears in the page",
                    severity=Severity.HIGH,
                    category="Sensitive data exposure",
                    description=(
                        "The document contains a string matching the AWS access key identifier format. If the key is "
                        "active, it may grant access to cloud resources depending on its policy."
                    ),
                    evidence="An AWS access key pattern was detected in the HTML response. The value is redacted.",
                    remediation="Remove the key, revoke it in AWS IAM, review CloudTrail for misuse and use short lived credentials.",
                    references=("https://cwe.mitre.org/data/definitions/798.html",),
                    cwe="CWE-798",
                )
            )
        if _GOOGLE_API_KEY.search(text):
            findings.append(
                Finding(
                    id="content.secrets.google_api_key",
                    check=self.id,
                    title="A Google API key pattern appears in the page",
                    severity=Severity.MEDIUM,
                    category="Sensitive data exposure",
                    description=(
                        "The document contains a string matching a Google API key format. Browser keys are sometimes "
                        "intended to be public, but they must be restricted by API, origin and quota to limit abuse."
                    ),
                    evidence="A Google API key pattern was detected in the HTML response. The value is redacted.",
                    remediation="Apply API and HTTP referrer restrictions to the key, rotate it if it is unrestricted and monitor quota usage.",
                    references=("https://cloud.google.com/docs/authentication/api-keys",),
                    cwe="CWE-798",
                )
            )
        return findings
