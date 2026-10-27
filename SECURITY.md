# Security Policy

## Supported versions

The latest released minor version receives security fixes. Older versions may receive a fix when the issue is critical and the upgrade path is short.

## Reporting a vulnerability in Web Guard

Please use GitHub private vulnerability reporting for this repository. Do not open a public issue for a vulnerability in the tool. Include the version, the command, the Python version, a minimal reproduction and the impact. Do not include real credentials, session cookies or third-party data.

## Reporting a vulnerability in a scanned target

Web Guard is not the security contact for the sites it scans. Report issues in a target to that site's owner through its published security contact or its `security.txt` document. Do not send third-party vulnerability details to this repository.

## Scope

A report about Web Guard itself should describe a defect in the scanner, the report writer, the configuration loader, the CLI or the packaging. Findings produced by an audit of another site are not vulnerabilities in Web Guard, even when the finding is serious. The tool is defensive and read-only, and it does not include an exploitation capability.
