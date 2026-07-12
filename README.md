# easypanel-mcp

Security-first [Model Context Protocol](https://modelcontextprotocol.io/) server
for bounded Easypanel observation and operations.

This project has two deliberately different deployment modes:

- **Local stdio** exposes the complete MCP tool set, including planning and
  guarded mutations. It is intended for a trusted MCP host on the same machine
  as the configuration and approval files.
- **Remote Streamable HTTP** runs as an Easypanel App Service and exposes only
  seven read-only observation tools. Plans and mutations are not reachable over
  the public listener.

The remote mode is the recommended first deployment. It does not require Node.js
on the client machine.

> Preview status: the automated security, protocol, gateway, and offline fixture
> suites pass. The repository has not been connected to a production Easypanel
> instance. Validate against a disposable instance before relying on it for
> operational work.

## Security properties

- No shell, container exec, Docker socket, raw RPC, arbitrary URL probing, or
  generic host administration.
- Explicit HTTPS origin, exact Host validation, independent bearer token, strict
  request/response limits, redirect rejection, and bounded upstream timeouts.
- Project allowlists are mandatory; wildcard access is rejected.
- Service inspection is a positive projection. Environment names may be shown,
  but values and credentials are never returned.
- Deployment log content is disabled in the first release.
- Remote HTTP is always `readonly`, uses one process-local session store, and
  fails closed if a request cannot be cancelled and settled.
- Local mutations require a fresh plan, external human approval, preconditions,
  post-action verification, and an audit record.

## Requirements

- Node.js `22.23.1` and npm `10.9.8` for local development.
- An Easypanel API token with the smallest practical scope.
- An explicit Easypanel version pin in `EASYPANEL_EXPECTED_VERSION`.

## Quick start: local stdio

```bash
git clone https://github.com/Yuhtin/easypanel-mcp.git
cd easypanel-mcp
npm ci
npm run build
```

Create a private environment for the MCP host. Do not commit it.

```bash
export EASYPANEL_URL="https://panel.example.com"
export EASYPANEL_TOKEN="<panel-token>"
export EASYPANEL_ACCESS_MODE="readonly"
export EASYPANEL_ALLOWED_PROJECTS="my-project"
export EASYPANEL_EXPECTED_VERSION="2.31.0"
export EASYPANEL_MCP_TRANSPORT="stdio"
node dist/index.js
```

An MCP client configuration is typically:

```json
{
  "mcpServers": {
    "easypanel": {
      "command": "node",
      "args": ["/absolute/path/to/easypanel-mcp/dist/index.js"],
      "env": {
        "EASYPANEL_URL": "https://panel.example.com",
        "EASYPANEL_TOKEN": "<panel-token>",
        "EASYPANEL_ACCESS_MODE": "readonly",
        "EASYPANEL_ALLOWED_PROJECTS": "my-project",
        "EASYPANEL_EXPECTED_VERSION": "2.31.0",
        "EASYPANEL_MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

The local server registers 14 tools. Read-only queries and plans are available
in `readonly`; every mutation remains blocked until the access mode, approval
artifacts, and policy allow it. See [`.env.example`](.env.example) for the full
configuration surface.

## Recommended deployment: remote Easypanel service

The complete step-by-step template is in
[`deploy/easypanel/README.md`](deploy/easypanel/README.md). The short version is:

1. Create an Easypanel **App Service** from an immutable release tag.
2. Let it build this `Dockerfile`; use internal port `3000`.
3. Attach one HTTPS domain and do not publish a host port.
4. Run exactly one replica and mount a persistent volume at `/app/.state`.
5. Store the following values as Easypanel secrets/environment variables:

```dotenv
EASYPANEL_MCP_TRANSPORT=http
EASYPANEL_MCP_HTTP_BIND_HOST=0.0.0.0
EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN=https://mcp.example.com
EASYPANEL_MCP_ACCESS_TOKEN=<random-independent-bearer>

EASYPANEL_URL=https://panel.example.com
EASYPANEL_TOKEN=<panel-token>
EASYPANEL_ACCESS_MODE=readonly
EASYPANEL_ALLOWED_PROJECTS=my-project
EASYPANEL_EXPECTED_VERSION=2.31.0
EASYPANEL_INSTANCE_LABEL=easypanel
EASYPANEL_TIMEOUT_MS=10000

EASYPANEL_AUDIT_PATH=/app/.state/audit.jsonl
EASYPANEL_APPROVAL_DIR=/app/.state/approvals
EASYPANEL_RUNTIME_LOCK_PATH=/app/.state/runtime.lock
```

The public token is separate from `EASYPANEL_TOKEN`. Generate it with a password
manager, keep it out of Git, and rotate it by updating the service environment.
The proxy must preserve the exact `Host` header and allow at least 75 seconds for
an MCP response. The request body limit is 128 KiB.

Connect a remote-capable MCP client with:

```json
{
  "mcpServers": {
    "easypanel": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <EASYPANEL_MCP_ACCESS_TOKEN>"
      }
    }
  }
}
```

The remote registry is intentionally exactly these seven tools:

| Tool | Purpose |
| --- | --- |
| `easypanel_list_projects` | List projects in the configured allowlist |
| `easypanel_list_services` | List sanitized services in one project |
| `easypanel_inspect_service` | Inspect a bounded public service projection |
| `easypanel_check_service_health` | Return status and readiness projections |
| `easypanel_list_deployments` | List bounded deployment summaries |
| `easypanel_get_deployment_status` | Read one target-bound deployment status |
| `easypanel_get_sanitized_logs` | Return the fixed “logs disabled” policy message |

`easypanel_capabilities`, planning, lifecycle, deploy, apply, rotation, and
destroy tools are deliberately unavailable over HTTP. The service starts only
after its Easypanel capability discovery succeeds, so the remote query budget is
bounded by the configured upstream timeout.

Check the service without credentials:

```bash
curl -i https://mcp.example.com/healthz
```

It should return `204`. `GET /mcp` should return `405`; there is no SSE endpoint,
CORS policy, browser login, URL token, or administrative route.

## Development and verification

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The tests use only the bundled fake fixture and mocked HTTP responses. They do not
contact a real Easypanel. The test runner canonicalizes the temporary directory
on macOS so the secure-path checks retain their no-symlink invariant.

To build the deployment image locally:

```bash
docker build --tag easypanel-mcp:local .
```

Release images should be built from an immutable Git tag and recorded by digest.
Use one replica and automatic restart in the hosting service.

## Scope and limitations

This server is not a general Easypanel console. It intentionally does not manage
hosts, Docker, mounts, certificates, backups, arbitrary service kinds, or runtime
WebSocket logs. Remote access currently represents one trusted bearer identity;
it is not a multi-user authorization system. Do not expose it without HTTPS and
an explicit project allowlist.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change and
[SECURITY.md](SECURITY.md) before reporting a vulnerability. Never include panel
tokens, approval keys, environment values, or private deployment URLs in issues
or pull requests.

## License

Apache-2.0. See [LICENSE](LICENSE).
