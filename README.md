# Web Guard

Web Guard is a defensive web security audit tool written in Python. It examines one HTTP or HTTPS target, applies nine groups of read-only checks, and writes a complete audit report in Markdown. The report explains the detected environment, the risk score, every finding, the evidence behind it, the recommended remediation and the limits of the assessment. A JSON representation of the same result is available for automation.

The scanner is intentionally conservative. It follows a bounded redirect chain, downloads a bounded response body, waits between requests and never authenticates, submits a form, injects a payload, brute forces a path or modifies remote state. It reports what ordinary unauthenticated clients can observe from the outside and deliberately avoids exploit attempts.

> **Authorization notice.** Use Web Guard only on systems that you own or that you have explicit written permission to test. An audit can generate log entries, trigger alarms and consume resources. The included authorization notice in every report is a reminder, not a legal authorization.

## Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Quick start](#quick-start)
5. [Checks](#checks)
6. [Command line reference](#command-line-reference)
7. [Configuration](#configuration)
8. [Reports](#reports)
9. [Scoring and exit codes](#scoring-and-exit-codes)
10. [Safety model and scope](#safety-model-and-scope)
11. [Project layout](#project-layout)
12. [Development](#development)
13. [Limitations](#limitations)
14. [License](#license)

## Features

Web Guard detects the target from a URL or host name, normalises the input to a single origin, resolves the final URL after redirects and fingerprints the response. It inspects response headers, cookies, the TLS handshake, HTML forms, embedded resources, a small fixed list of sensitive paths and the `security.txt` location. Every check runs in isolation, so a failed request produces a check error instead of aborting the audit.

The output is designed to be useful to engineers, reviewers and clients. The Markdown report contains an executive summary, a risk overview, the detected environment, a findings table, detailed findings with evidence and remediation, the executed checks, the methodology, the limitations and the scoring model. Cookie values, query string values and detected secret values are redacted or omitted. Response bodies are never copied into the report.

The implementation uses only the Python standard library at runtime. There are no transitive runtime dependencies, no database, no daemon and no browser automation. The CLI is the only supported entry point, and the library API is available for integration and testing.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability in Web Guard itself and how to handle a vulnerability found in a scanned target.

## Requirements

Web Guard requires Python 3.11 or newer. It runs on Linux, macOS and Windows wherever the standard library provides sockets, TLS and `tomllib`. Development requires pytest for the test suite, optionally pytest-cov for coverage, and ruff for linting.

## Installation

Install from a checkout in editable mode so that the `web-guard` command tracks the source tree.

```console
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

For development tools, install the optional group instead.

```console
python3 -m pip install -e ".[dev]"
```

The package can also be installed without a virtual environment with `python3 -m pip install .`. The command is exposed as `web-guard`, and the module form `python3 -m web_guard` behaves identically.

## Quick start

Scan a site and write a timestamped Markdown report to the current directory.

```console
web-guard scan https://example.com
```

Write to a chosen path and request both Markdown and JSON.

```console
web-guard scan https://example.com -o reports/example --format both
```

Send only the headers and cookies checks and never fail the process because of a finding.

```console
web-guard scan example.com --checks headers,cookies --fail-on none
```

List the available checks without touching the network.

```console
web-guard checks
```

Print the report to standard output instead of a file.

```console
web-guard scan https://example.com -o - | less
```

Use a configuration file for repeatable team settings.

```console
web-guard scan https://example.com --config web-guard.toml
```

## Checks

Web Guard executes nine checks in a stable order. Each check has a stable identifier that can be used with `--checks`, `--exclude-checks` and the configuration file.

| Identifier | Name | What it examines |
| --- | --- | --- |
| `transport` | HTTPS and TLS | HTTPS enforcement, HTTPS downgrade redirects, certificate trust and expiry, negotiated protocol version and weak cipher components. |
| `headers` | HTTP security headers | HSTS and its max-age, Content-Security-Policy and common unsafe directives, clickjacking protection, MIME sniffing, Referrer-Policy, Permissions-Policy, COOP and CORP. |
| `cookies` | Cookie security | Secure, HttpOnly and SameSite attributes, SameSite=None without Secure, and the `__Host-` and `__Secure-` prefix rules. Values are never recorded. |
| `cors` | CORS policy | Reflected origins, reflected origins combined with credentials, wildcard origins, the null origin and invalid multiple-origin values. |
| `methods` | HTTP methods | OPTIONS method advertisements and whether TRACE reflects a unique request marker, which would confirm Cross-Site Tracing exposure. |
| `disclosure` | Information disclosure | Server and framework version banners, debug headers, generator metadata, directory listings and verbose error pages on a nonexistent path. |
| `content` | Content and forms | Active and passive mixed content, password forms over HTTP or with GET, insecure form actions, script or data form actions, missing anti-CSRF token heuristics, reverse tabnabbing and embedded secret patterns. |
| `files` | Exposed sensitive files | A fixed list of nine paths including `.env`, `.env.bak`, `.git/HEAD`, `.git/config`, `wp-config.php.bak`, `backup.sql`, `phpinfo.php`, `server-status` and `.DS_Store`, each confirmed by a content signature and a soft-404 baseline. |
| `wellknown` | Security contact metadata | The `/.well-known/security.txt` document and whether it declares a Contact field. |

The checks are deliberately independent. A site with no HTML is still evaluated for transport, headers, cookies, CORS, methods, disclosure, sensitive files and `security.txt`. The content check returns no findings when the response is not HTML and records that limitation in the executed checks table.

## Command line reference

The CLI has three commands. `scan` performs an audit, `checks` prints the check catalogue and `version` prints the installed version.

```text
web-guard scan TARGET [options]
web-guard checks
web-guard version
```

`TARGET` may include a scheme and path. When the scheme is omitted, Web Guard assumes HTTPS and may fall back to HTTP only when the implicit HTTPS connection cannot be established. Credentials in URLs, unsupported schemes, whitespace, control characters and invalid host names are rejected before any request is sent.

| Option | Meaning |
| --- | --- |
| `-o`, `--output PATH` | Write the report to `PATH`. Use `-` for standard output. The default is a timestamped file in the current directory. |
| `--format {md,json,both}` | Choose Markdown, JSON or both. Default: `md`. `both` cannot be combined with standard output. |
| `--config PATH` | Load a TOML configuration file. Command line options override file values. |
| `--checks LIST` | Comma separated check identifiers to run. Default: all checks. |
| `--exclude-checks LIST` | Comma separated check identifiers to skip. A check cannot be both included and excluded. |
| `--list-checks` | Print the catalogue and exit without a target. |
| `--fail-on LEVEL` | Exit with code 2 when a finding at or above this level exists. Accepts `none`, `info`, `low`, `medium`, `high` or `critical`. Default: `high`. |
| `--timeout SECONDS` | Per-request timeout between 0.1 and 120 seconds. Default: 10. |
| `--delay SECONDS` | Minimum delay between requests between 0 and 60 seconds. Default: 0.25. |
| `--max-redirects COUNT` | Maximum redirects to follow between 0 and 50. Default: 5. |
| `--max-body-bytes BYTES` | Maximum response body to inspect between 1024 and 20971520. Default: 2097152. |
| `--user-agent VALUE` | Override the descriptive default User-Agent. Line breaks are rejected. |
| `--cors-origin ORIGIN` | Origin sent by the CORS probe. Default: `https://webguard.invalid`, which is reserved and harmless. |
| `--insecure` | Disable TLS certificate verification. The scan still reports the certificate as untrusted. Use only after confirming the target is trusted. |
| `--no-tls-probe` | Do not probe port 443 when the target itself is served over HTTP. |
| `-q`, `--quiet` | Suppress the terminal summary. Errors and the threshold message still use standard error. |
| `-v`, `--verbose` | Enable debug logging, including check failures and command tracebacks. |
| `--no-color` | Disable ANSI colours. The `NO_COLOR` environment variable has the same effect. |
| `--version` | Print the version and exit. |

Exit code zero means the scan completed and no finding reached the configured threshold. Exit code one means the scan could not start or complete, for example because the target was invalid, the initial document could not be retrieved or the configuration was rejected. Exit code two means the scan completed but a finding at or above the threshold exists. Exit code 130 means the user interrupted the process.

## Configuration

Configuration is optional. The file is TOML and accepts three top-level tables: `scanner`, `checks` and `report`. Unknown tables and unknown scanner keys are rejected so that a typo cannot silently change a security test. Explicit command line options always override scanner values from the file.

```toml
[scanner]
timeout = 10.0
delay = 0.5
max_redirects = 5
max_body_bytes = 2097152
user_agent = "WebGuard/1.0.0 (authorized audit; security@example.com)"
verify_tls = true
probe_tls = true
cors_origin = "https://webguard.invalid"

[checks]
include = ["transport", "headers", "cookies", "cors", "methods", "disclosure", "content", "files", "wellknown"]
exclude = []

[report]
fail_on = "high"
```

A shorter file is equally valid. The following configuration restricts the audit to headers and cookies and disables the threshold exit.

```toml
[checks]
include = ["headers", "cookies"]

[report]
fail_on = "none"
```

The `checks.include` and `checks.exclude` values must be lists of strings. An empty include list means all checks. The `report.fail_on` value must be a severity name or the string `none`. The scanner keys are validated with the same ranges as the CLI options, including the 1024 byte lower bound on the body limit and the 120 second upper bound on the timeout.

## Reports

The Markdown report is the primary deliverable. It has a stable structure so that it can be archived, reviewed and compared between scans. The header records the requested and final URL, the start time, the duration, the tool version, the generation time and the number of requests. The authorization notice is repeated there. The executive summary describes the outcome in prose and names the most urgent issues. The risk overview contains the score, grade, risk label, severity counts and the weight of each severity. The detected environment section lists the status, title, IP address, server banner, runtime header, content type, inspected body size, HTTP version, response time, redirect chain, inferred technologies and TLS fields when available.

The findings summary is a single table ordered by severity and identifier. The detailed findings section groups findings by severity, and every finding records its identifier, severity, producing check, category, CWE reference, prose description, evidence block, remediation and references. Evidence is deliberately limited to metadata and safe excerpts. Cookie values, query string values and secret values are redacted or omitted, as are raw response bodies. The executed checks table shows whether a check passed, reported issues, was skipped or failed, together with its duration and a short explanatory detail. The methodology, limitations and scoring sections explain how to interpret the result and where the automated assessment stops.

The JSON report contains the same information in a machine-readable shape. It includes the target, final URL, timestamps, duration, detection object, outcomes, findings, score, grade, risk, severity counts, request count and tool version. It is intended for dashboards and regression tracking, not as a replacement for the prose report.

By default the filename is `web-guard-report-HOST-TIMESTAMP.md`, with the port appended when it is not the scheme default. With `--format both`, the same base name is used with `.md` and `.json` suffixes. If an explicit output path already has a recognised extension, `--format md` keeps it and `--format json` keeps it, while `--format both` removes the extension and adds both suffixes.

## Scoring and exit codes

The score starts at 100. Every finding subtracts a fixed weight: 40 for critical, 20 for high, 8 for medium and 3 for low. Informational findings carry no weight because they describe observations that are not vulnerabilities on their own. The result is clamped to the range 0 to 100. The grade is A for 90 and above, B for 80, C for 70, D for 60, E for 40 and F below 40. The risk label is critical when any critical finding exists, low at 90 or above, moderate at 75 or above, elevated at 50 or above, high at 25 or above and critical below 25. A critical finding therefore always produces a critical risk label even if the numeric score would otherwise suggest a lower risk.

The weight table is intentionally simple and transparent. It is not CVSS and it does not attempt to model exploitability, data sensitivity or business context. It is designed to be stable across runs, easy to explain and difficult to game. A single critical exposure, such as a public `.env` file, dominates the score because it can lead directly to a full compromise. Many informational observations cannot hide a serious finding because they do not reduce the score at all.

The `--fail-on` option converts the result into a process status for CI. The default threshold is `high`, so a high or critical finding exits with code 2. Use `--fail-on none` or `report.fail_on = "none"` when the audit is exploratory, and choose `--fail-on medium` or a stricter value when the pipeline should enforce hardening. The exit code is independent of the report: the report is written before the threshold is evaluated.

## Safety model and scope

Web Guard is a read-only external scanner. It requests the target document, follows a bounded redirect chain, performs an OPTIONS request, performs a TRACE request with a unique marker, performs one GET with a synthetic Origin header for CORS, requests one random nonexistent path for a soft-404 baseline, requests a fixed list of nine sensitive paths and requests `/.well-known/security.txt`. It does not log in, submit a form, upload a file, send a payload, fuzz a parameter, enumerate users, brute force a path or change remote state.

Every request is subject to the configured timeout, the delay and the body size limit. Redirects are capped and only HTTP and HTTPS are accepted. The response body is decoded conservatively and truncated. The HTML parser is tolerant of malformed markup and caps the number of forms, inputs, resources, links, comments and title characters it retains. A hostile page therefore cannot make the scanner allocate unbounded memory through these collections.

The target is chosen by the operator and is validated before the first request. Web Guard is not a hosted service and does not accept remote scan submissions. It does not follow redirects to a scheme other than HTTP or HTTPS and does not use the target URL as a generic proxy. The descriptive User-Agent and the default delay make the traffic identifiable and polite. Operators remain responsible for authorization, for the load placed on the target and for any local law or contract that applies.

Reports are written to be shareable. Cookie names are recorded but values are not. URLs in report tables and evidence have query values redacted. Secret patterns are reported by class without the matched value. Raw response bodies are never embedded. The sensitive file check records only the path, status, content type and the name of the matched signature. These choices reduce the chance that the audit report becomes a second data leak.

## Project layout

```text
.
├── pyproject.toml
├── Makefile
├── README.md
├── SECURITY.md
├── LICENSE
├── src
│   ├── __init__.py
│   ├── __main__.py
│   ├── check_base.py
│   ├── check_content.py
│   ├── check_cookies.py
│   ├── check_cors.py
│   ├── check_disclosure.py
│   ├── check_headers.py
│   ├── check_methods.py
│   ├── check_sensitive_files.py
│   ├── check_transport.py
│   ├── check_wellknown.py
│   ├── checks.py
│   ├── cli.py
│   ├── config.py
│   ├── errors.py
│   ├── html.py
│   ├── http_client.py
│   ├── models.py
│   ├── py.typed
│   ├── report.py
│   ├── scanner.py
│   ├── scoring.py
│   ├── target.py
│   ├── utils.py
│   └── version.py
└── tests
    ├── conftest.py
    ├── helpers.py
    └── test_*.py
```

The source modules live directly in `src`. The build maps that directory to the installed `web_guard` package through `[tool.setuptools.package-dir]`, so imports remain `web_guard.cli`, `web_guard.scanner` and `web_guard.checks`, and the console entry point is unchanged. The scanner orchestration lives in `scanner.py`, the check implementations in the `check_*.py` modules, the check registry in `checks.py`, the HTTP and TLS transport in `http_client.py`, the tolerant HTML parser in `html.py`, the report renderers in `report.py` and the CLI in `cli.py`. The public interface is re-exported from `src/__init__.py`, and `py.typed` marks the package as typed.

## Development

The test suite uses real loopback HTTP and HTTPS servers for transport behaviour and small deterministic context builders for individual checks. It covers target normalisation, configuration validation, HTTP redirects, timeouts, truncation, TLS probing, HTML tolerance, every check, scoring, report rendering, the scanner orchestration and the CLI. Run it with the Makefile target or directly.

```console
make test
```

The direct command, which also works without the package being installed, is:

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider
```

The test bootstrap in `tests/conftest.py` loads the flat `src` tree under the `web_guard` package name, so the suite does not require an editable install or `PYTHONPATH`. An installed package uses the mapping in `pyproject.toml` instead.

Run the coverage target after installing the development dependencies.

```console
make coverage
```

Run the linter with ruff.

```console
python3 -m ruff check src tests
```

The `make clean` target removes bytecode caches, pytest and ruff caches, coverage artefacts, build directories, egg information and generated reports. It is safe to run before committing. The project has no generated files that are required at runtime.

## Limitations

Web Guard performs an external, unauthenticated audit of a single entry point. It cannot find vulnerabilities that require a signed-in session, a multi-step business process, a race condition, a file upload, a payment flow or access to internal infrastructure. It does not crawl the site, enumerate virtual hosts, brute force paths or credentials, fuzz parameters, execute JavaScript, follow single page application routes or inspect third-party dependencies. TLS inspection reports the negotiated connection but does not enumerate every protocol and cipher suite the server might accept. A WAF, a CDN cache, a load balancer or a geographic difference can make one response unrepresentative. The CSRF token heuristic, the technology fingerprint and the session cookie heuristic can produce false positives and should be confirmed manually. A clean result is not a certification of security. Use the report as a prioritised starting point for a broader assessment that includes authenticated testing, code review and threat modelling.

## License

Web Guard is released under the MIT License. See `LICENSE` for the full text. The software is provided without warranty and must be used only on systems for which authorization has been granted.
