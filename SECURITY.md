# Security policy

## Supported versions

Only the latest release on the default branch is supported. The remote service
should be upgraded from immutable release tags.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository:

<https://github.com/Yuhtin/easypanel-mcp/security/advisories/new>

Do not open a public issue containing a panel URL, API token, bearer token,
approval key, environment value, deployment identifier, or private logs.

Include a minimal reproduction, affected version, impact, and whether the issue
affects local stdio, remote HTTP, or both. We will acknowledge reports as soon as
practical and coordinate disclosure after a fix is available.

## Operational reporting

If a credential may have been exposed, rotate it immediately in Easypanel and in
the MCP host/service environment before investigating logs or opening a report.
