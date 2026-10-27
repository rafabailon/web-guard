"""Audit orchestration.

The scanner owns the request budget, performs target detection once and then
runs every selected check against a shared context. Checks are isolated: one
failing check produces an error outcome but never prevents the report from being
written. No check is retried, and every request is subject to the same rate
limit and redirect cap.
"""

from __future__ import annotations

import logging
import socket
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from urllib.parse import urljoin

from .checks import Check, ScanContext, build_checks
from .config import Settings
from .errors import CheckSkipped, ConfigError, RequestError, ScanError
from .html import PageInfo, parse_html
from .http_client import HttpClient, HttpResponse, probe_tls, tls_probe_target
from .models import (
    CheckOutcome,
    CheckStatus,
    Detection,
    ScanResult,
    TlsInfo,
    flatten_findings,
)
from .scoring import score_summary
from .target import Target, target_from_input
from .utils import is_html_content_type
from .version import __version__

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str], None]


def scan(
    target: str,
    settings: Settings | None = None,
    checks: Sequence[Check] | None = None,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Audit one target and return a complete result.

    The method raises ScanError when the initial document cannot be retrieved,
    because no meaningful report can be produced without it. Configuration and
    selection errors are raised before any network traffic occurs.
    """

    settings = settings or Settings()
    selected_checks = list(checks) if checks is not None else build_checks()
    if not selected_checks:
        raise ConfigError("At least one check must be selected.")
    target_info = target_from_input(target)
    started_at = datetime.now(tz=UTC)
    started = time.perf_counter()

    client = HttpClient(settings)
    response, target_info = _fetch_main_document(target_info, client)
    page = parse_html(response.text) if _looks_like_html(response) else None
    tls = _resolve_tls(response, settings)
    detection = _build_detection(target_info, response, page, tls)
    not_found = _probe_not_found(response, client)
    context = ScanContext(
        target=target_info,
        response=response,
        client=client,
        settings=settings,
        detection=detection,
        page=page,
        not_found=not_found,
    )

    outcomes: list[CheckOutcome] = []
    for check in selected_checks:
        if progress is not None:
            progress(check.id, check.name)
        logger.debug("Running check %s", check.id)
        check_started = time.perf_counter()
        try:
            findings = check.run(context)
            status = CheckStatus.ISSUES if findings else CheckStatus.PASSED
            detail = "" if findings else "No issues detected."
        except CheckSkipped as exc:
            findings = []
            status = CheckStatus.SKIPPED
            detail = str(exc)
        except Exception as exc:  # Checks must never abort the whole audit.
            logger.debug("Check %s failed", check.id, exc_info=True)
            findings = []
            status = CheckStatus.ERROR
            detail = f"{type(exc).__name__}: {exc}"
        duration_ms = (time.perf_counter() - check_started) * 1000
        outcomes.append(
            CheckOutcome(
                check_id=check.id,
                name=check.name,
                status=status,
                findings=findings,
                detail=detail,
                duration_ms=duration_ms,
            )
        )

    findings = flatten_findings(outcomes)
    findings.sort(key=lambda item: (-item.severity.rank, item.id))
    score, grade, risk = score_summary(findings)
    duration = time.perf_counter() - started
    return ScanResult(
        target=target_info.url,
        final_url=response.url,
        started_at=started_at,
        duration_seconds=duration,
        detection=detection,
        outcomes=outcomes,
        findings=findings,
        score=score,
        grade=grade,
        risk=risk,
        tool_version=__version__,
        checks_requested=tuple(check.id for check in selected_checks),
        request_count=client.request_count,
        settings=settings.to_dict(),
    )


def _fetch_main_document(target: Target, client: HttpClient) -> tuple[HttpResponse, Target]:
    """Fetch the main document, optionally falling back from HTTPS to HTTP.

    A missing scheme is treated as an explicit request to discover the site. If
    HTTPS cannot be reached at all, HTTP is attempted and the normal transport
    checks report the downgrade. Certificate validation failures do not trigger
    the fallback because silently auditing HTTP would conceal the trust problem;
    the operator is asked to make an explicit decision with --insecure.
    """

    try:
        response = client.request(target.url)
        return response, target
    except RequestError as https_error:
        message = str(https_error).lower()
        if "certificate verification failed" in message:
            raise ScanError(
                f"HTTPS certificate validation failed for {target.host}. "
                "Inspect the certificate, or re-run with --insecure to audit the site anyway."
            ) from https_error
        if not (target.implicit_scheme and target.scheme == "https"):
            raise ScanError(f"Could not retrieve {target.url}: {https_error}") from https_error
        fallback_url = f"http://{target.url[len('https://'):]}"
        try:
            fallback_target = target_from_input(fallback_url)
            response = client.request(fallback_target.url)
            return response, fallback_target
        except RequestError as http_error:
            raise ScanError(
                "The target could not be reached over HTTPS or HTTP. "
                f"HTTPS error: {https_error}. HTTP error: {http_error}."
            ) from http_error


def _resolve_tls(response: HttpResponse, settings: Settings) -> TlsInfo | None:
    """Return TLS metadata from the response or a polite HTTPS probe."""

    if response.url.startswith("https://"):
        return response.tls
    if not settings.probe_tls:
        return None
    probe = tls_probe_target(response.url)
    if probe is None:
        return None
    host, port = probe
    if not host:
        return None
    try:
        return probe_tls(host, port, timeout=min(settings.timeout, 5.0))
    except Exception:
        logger.debug("Standalone TLS probe failed", exc_info=True)
        return None


def _probe_not_found(response: HttpResponse, client: HttpClient) -> HttpResponse | None:
    """Request a random path to obtain a soft-404 baseline and error sample."""

    probe_url = urljoin(response.url, f"/webguard-probe-{uuid.uuid4().hex}")
    try:
        return client.request(probe_url)
    except RequestError:
        return None


def _build_detection(
    target: Target,
    response: HttpResponse,
    page: PageInfo | None,
    tls: TlsInfo | None,
) -> Detection:
    """Assemble the fingerprint section of the report."""

    server = response.header("server").strip()
    powered_by = response.header("x-powered-by").strip()
    return Detection(
        requested_url=target.url,
        final_url=response.url,
        status_code=response.status,
        title=page.title if page else "",
        ip_address=_resolve_ip(target.host),
        server=server,
        powered_by=powered_by,
        content_type=response.content_type,
        content_length=len(response.body),
        http_version=response.http_version,
        response_time_ms=response.elapsed_ms,
        redirect_chain=response.redirect_chain,
        technologies=tuple(_detect_technologies(response, page)),
        tls=tls,
    )


def _resolve_ip(host: str) -> str:
    """Resolve the target host to a representative IP address."""

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return ""
    if not results:
        return ""
    return results[0][4][0]


def _looks_like_html(response: HttpResponse) -> bool:
    """Decide whether the main response should be parsed as HTML."""

    if is_html_content_type(response.header("content-type")):
        return True
    return bool(not response.header("content-type") and b"<html" in response.body[:2048].lower())


def _detect_technologies(response: HttpResponse, page: PageInfo | None) -> list[str]:
    """Identify common server, framework and CMS technologies from weak signals."""

    body = response.text[:200_000].lower()
    headers = " ".join(
        f"{name}: {value}" for name, values in response.headers.items() for value in values
    ).lower()
    cookies = " ".join(response.cookies).lower()
    server = response.header("server").lower()
    powered_by = response.header("x-powered-by").lower()
    detected: list[str] = []

    server_signatures = (
        ("cloudflare", "Cloudflare"),
        ("nginx", "Nginx"),
        ("apache", "Apache HTTP Server"),
        ("microsoft-iis", "Microsoft IIS"),
        ("litespeed", "LiteSpeed"),
        ("caddy", "Caddy"),
        ("openresty", "OpenResty"),
        ("gunicorn", "Gunicorn"),
        ("uvicorn", "Uvicorn"),
    )
    combined_server = f"{server} {headers}"
    for marker, label in server_signatures:
        if marker in combined_server:
            detected.append(label)

    runtime_signatures = (
        ("php", "PHP"),
        ("asp.net", "ASP.NET"),
        ("express", "Express"),
        ("node.js", "Node.js"),
        ("python", "Python"),
        ("ruby", "Ruby"),
    )
    for marker, label in runtime_signatures:
        if marker in powered_by or (label == "PHP" and "phpsessid" in cookies):
            detected.append(label)

    cms_signatures = {
        "WordPress": ("wp-content/", "wp-includes/"),
        "Drupal": ("sites/default/files/", "drupal"),
        "Joomla": ("/media/system/js/", "joomla"),
        "Next.js": ("__next_data__", "/_next/"),
        "Nuxt": ("__nuxt__", "/_nuxt/"),
        "Angular": ("ng-version", "ng-app"),
        "Vue.js": ("data-v-", "__vue__"),
        "React": ("data-reactroot", "react-dom"),
        "Rails": ("csrf-token", "_rails"),
        "Laravel": ("laravel_session", "xsrf-token"),
        "Django": ("csrfmiddlewaretoken", "csrftoken"),
        "Spring": ("whitelabel error page", "x-application-context"),
    }
    for label, markers in cms_signatures.items():
        if any(marker in body or marker in cookies for marker in markers):
            detected.append(label)

    if page and page.meta_generator:
        generator = page.meta_generator.split()[0]
        if generator:
            detected.append(generator)
    if response.url.endswith(".php") or ".php" in response.url:
        detected.append("PHP")
    return sorted(set(detected))
