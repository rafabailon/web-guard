"""Tests for sensitive file exposure checks."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from helpers import FakeClient, make_context, make_response
from web_guard.check_sensitive_files import SensitiveFilesCheck
from web_guard.errors import CheckSkipped, RequestError

BASE = "https://example.test/"


def make_client(responses, default_status=404, default_body="Not Found"):
    def handler(url, method, headers):
        path = urlsplit(url).path
        if path in responses:
            return responses[path]
        return make_response(url, status=default_status, body=default_body)

    return FakeClient(handler)


def run(responses, not_found=None):
    client = make_client(responses)
    context = make_context(url=BASE, client=client, not_found=not_found)
    return SensitiveFilesCheck().run(context)


def ids(findings):
    return {finding.id for finding in findings}


def test_dotenv_exposure_is_critical_and_body_is_redacted():
    response = make_response(f"{BASE}.env", status=200, body="SECRET_KEY=topsecret\nDB_PASSWORD=abc")
    findings = run({"/.env": response})
    finding = next(item for item in findings if item.id == "files.dotenv")
    assert finding.severity.value == "critical"
    assert "topsecret" not in finding.evidence


def test_git_and_backup_exposures_are_detected():
    findings = run(
        {
            "/.git/HEAD": make_response(f"{BASE}.git/HEAD", body="ref: refs/heads/main\n"),
            "/.git/config": make_response(f"{BASE}.git/config", body="[core]\n\trepositoryformatversion = 0\n"),
            "/.env.bak": make_response(f"{BASE}.env.bak", body="APP_KEY=abc\n"),
            "/wp-config.php.bak": make_response(f"{BASE}wp-config.php.bak", body="define('DB_PASSWORD', 'x');"),
            "/backup.sql": make_response(f"{BASE}backup.sql", body="CREATE TABLE users (id int);"),
        }
    )
    assert {
        "files.git_head",
        "files.git_config",
        "files.dotenv_backup",
        "files.wp_config_backup",
        "files.backup_sql",
    } <= ids(findings)


def test_phpinfo_and_server_status_are_detected():
    findings = run(
        {
            "/phpinfo.php": make_response(f"{BASE}phpinfo.php", body="<title>PHP Version 8.2</title>"),
            "/server-status": make_response(f"{BASE}server-status", body="Apache Server Status for localhost"),
        }
    )
    assert "files.phpinfo" in ids(findings)
    assert "files.server_status" in ids(findings)


def test_ds_store_is_low_severity():
    findings = run({"/.DS_Store": make_response(f"{BASE}.DS_Store", body=b"\x00\x00\x00\x01Bud1")})
    finding = next(item for item in findings if item.id == "files.ds_store")
    assert finding.severity.value == "low"


def test_soft_404_baseline_is_ignored():
    not_found = make_response(f"{BASE}missing", status=200, body="APP_NAME=demo\n")
    response = make_response(f"{BASE}.env", status=200, body="APP_NAME=demo\n")
    findings = run({"/.env": response}, not_found=not_found)
    assert "files.dotenv" not in ids(findings)


def test_html_error_page_does_not_trigger_signature():
    response = make_response(f"{BASE}.env", status=200, body="<html><body>Not found</body></html>")
    assert run({"/.env": response}) == []


def test_non_success_status_is_ignored():
    response = make_response(f"{BASE}.env", status=403, body="SECRET_KEY=abc")
    assert run({"/.env": response}) == []


def test_all_failed_requests_skip_check():
    client = FakeClient(lambda *_args: RequestError("offline"))
    with pytest.raises(CheckSkipped):
        SensitiveFilesCheck().run(make_context(url=BASE, client=client))


def test_probe_urls_are_root_relative():
    client = make_client({})
    SensitiveFilesCheck().run(make_context(url="https://example.test/app/page", client=client))
    requested = [url for url, _method, _headers in client.calls]
    assert f"{BASE}.env" in requested
    assert all(url.startswith(BASE) for url in requested)
