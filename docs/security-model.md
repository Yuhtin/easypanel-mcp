# Security model

This document describes the boundaries that a deployment must preserve. It is a
design reference, not a substitute for reviewing the configuration of the host
running the MCP service.

## Trust boundaries

```text
MCP client ── authenticated MCP transport ──> easypanel-mcp ── HTTPS ──> Easypanel
                                                   │
                                      policy, allowlist, projection, audit
```

The panel is an upstream dependency and may return malformed, oversized, stale,
or untrusted content. The server validates response shape, limits body size,
rejects redirects, and exposes only positive projections.

## Local stdio

The local process receives MCP frames from its parent process. Frame size,
outbound queue size, JSON depth, response size, and concurrent tool calls are
bounded. The local process can create plans and, when explicitly configured,
apply mutations. A mutation requires:

1. an allowlisted target and valid desired state;
2. a fresh plan with precondition and capability hashes;
3. a separate human-created approval artifact;
4. a second confirmation artifact for critical operations;
5. target-bound dispatch, verification, and audit.

The approval key and secret references belong to the operator's secret store. They
must never be supplied as tool arguments or committed to Git.

## Remote Streamable HTTP

Remote mode rejects every access mode except `readonly`. The edge requires:

- HTTPS origin configuration and an exact Host header;
- one independent bearer token in the Authorization header;
- exact `/mcp` and `/healthz` routes;
- JSON request bodies with bounded bytes and strict UTF-8;
- one authenticated request at a time per session;
- one replica with persistent local state.

The edge filters `tools/list` and rejects `tools/call` before the MCP SDK unless
the name is one of the seven observation tools documented in the README. The
capability-refresh tool is intentionally excluded so the successful startup
discovery remains stable for the remote query deadline budget.

An application deadline is propagated through the asynchronous invocation context
to each upstream fetch and response-body reader. A timeout aborts that work and
keeps the MCP transport alive until its original request promise settles. If a
handler ignores cancellation beyond the recovery grace, the listener stops and
the production process exits non-zero so a supervisor can replace it. The service
never closes an SDK JSON transport while its response resolver is still pending.

## Data handling

- Environment values, credentials, bearer tokens, and upstream error bodies are
  redacted or discarded before MCP output.
- Deployment logs are not fetched in the first release.
- Audit events use a fixed schema and private append-only files.
- State directories and approval artifacts require private ownership and mode
  `0700`/`0600`.
- The fake fixture and tests do not perform network calls.

## Operational assumptions

Remote mode represents one trusted bearer identity, not a multi-user policy. Put
it behind an HTTPS proxy, do not publish the container port, restrict the project
allowlist, configure automatic restart, and rotate both panel and MCP tokens when
access changes.
