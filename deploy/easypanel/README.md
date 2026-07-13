# Deploy on Easypanel (remote, read-only)

This is the recommended installation path when the MCP client should not run
Node.js locally. The application runs as one Easypanel App Service, receives HTTPS
from the panel proxy, and exposes `POST`/`DELETE /mcp` plus `GET /healthz`.

Remote mode is intentionally and permanently read-only for this release. Planning
and mutation tools remain available only through local stdio/SSH while the
approval model is local-file based.

## 1. Create the service

Create an **App Service** with the **Docker Image** source. Use the image from the
release workflow, for example:

```text
ghcr.io/yuhtin/easypanel-mcp:0.1.0
```

For this release, the digest is:

```text
ghcr.io/yuhtin/easypanel-mcp@sha256:c3efdef905b0506c86520d25e7d8b7b21ec1ba3eec8d6e82ecb67dc1e740528f
```

Pin the digest shown in the GitHub Actions summary for later releases. Using the Git
repository and `Dockerfile` is still supported for development, but it makes each
Easypanel deploy rebuild the image.

- Configure a domain such as `mcp.example.com`, proxying to internal port `3000`,
  with HTTPS enabled.
- Do not publish a host port. The service must be reachable only through the HTTPS
  domain.
- Use exactly one replica. Sessions and audit state are intentionally local.
- Mount a persistent volume, for example `mcp-state`, at `/app/.state`.
- Enable automatic restart. The process exits non-zero if a request ignores
  cancellation beyond the recovery grace period.

## 2. Add environment variables

Put secrets in Easypanel's secret environment fields, never in Git or the MCP
client configuration.

```dotenv
EASYPANEL_MCP_TRANSPORT=http
EASYPANEL_MCP_HTTP_BIND_HOST=0.0.0.0
EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN=https://mcp.example.com
EASYPANEL_MCP_ACCESS_TOKEN=<random-independent-bearer-at-least-32-chars>

EASYPANEL_URL=https://panel.example.com
EASYPANEL_TOKEN=<least-privileged-panel-token>
EASYPANEL_ACCESS_MODE=readonly
EASYPANEL_ALLOWED_PROJECTS=my-project
EASYPANEL_EXPECTED_VERSION=<exact-panel-version>
EASYPANEL_INSTANCE_LABEL=easypanel
EASYPANEL_TIMEOUT_MS=10000

EASYPANEL_AUDIT_PATH=/app/.state/audit.jsonl
EASYPANEL_APPROVAL_DIR=/app/.state/approvals
EASYPANEL_RUNTIME_LOCK_PATH=/app/.state/runtime.lock
```

`EASYPANEL_MCP_ACCESS_TOKEN` is not the panel token. Generate it with a password
manager and rotate it through the service environment. Remote startup fails
closed when the public origin is not HTTPS, the token is missing, the project
allowlist contains `*`, the host does not match exactly, or access mode is not
`readonly`.

Configure a proxy response timeout of at least 75 seconds and a request body limit
of at most 128 KiB. Preserve the exact `Host` header; do not rely on
`X-Forwarded-*` fallback.

## 3. Connect an MCP client

Use the remote/Streamable HTTP configuration supported by your client:

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

Call `easypanel_list_projects` first and confirm that only expected projects are
visible. The remote registry contains exactly seven observation tools:

- `easypanel_list_projects`
- `easypanel_list_services`
- `easypanel_inspect_service`
- `easypanel_check_service_health`
- `easypanel_list_deployments`
- `easypanel_get_deployment_status`
- `easypanel_get_sanitized_logs`

It does not publish `easypanel_capabilities`, plans, lifecycle, deploy, apply,
rotation, or destroy tools. A direct call to an omitted tool is rejected before
the MCP SDK.

## 4. Verify the service

```bash
curl -i https://mcp.example.com/healthz
```

Expected behavior:

- `/healthz` returns `204`.
- `GET /mcp` returns `405`.
- `POST /mcp` without the bearer returns `401`.
- No CORS, SSE, Docker socket, shell, public host port, or administration route
  is available.
