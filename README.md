<div align="center">

# easypanel-mcp

**Connect your AI agent to Easypanel. Read-only by default.**

<p>
  <a href="https://github.com/Yuhtin/easypanel-mcp/actions/workflows/ci.yml"><img src="https://github.com/Yuhtin/easypanel-mcp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Yuhtin/easypanel-mcp/pkgs/container/easypanel-mcp"><img src="https://img.shields.io/badge/GHCR-public-blue?logo=docker" alt="GHCR image"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="Apache 2.0 license"></a>
</p>

<img src="docs/assets/easypanel-mcp.svg" alt="MCP client connected over HTTPS to a read-only Easypanel MCP service" width="900">

</div>

Give Claude, ChatGPT, Cursor, or any MCP client a safe view of your Easypanel
projects, services, health, deployments, and sanitized logs.

## Start here (recommended)

Run it as one Easypanel App Service. There is no Node.js installation on your
computer and no repository build step.

### 1. Create the service

In Easypanel: **New Service → App Service → Docker Image**.

Paste this image:

```text
ghcr.io/yuhtin/easypanel-mcp:latest
```

`latest` is updated automatically whenever a new release is published.

Set:

- internal port: `3000`
- one replica
- HTTPS domain, for example `https://mcp.example.com`
- persistent volume: `/app/.state`
- automatic restart enabled
- no public host port

### 2. Add the environment variables

Generate a random value (at least 32 characters recommended) in your password
manager and use it as the MCP access token. Do not use your Easypanel API token
for this value.

Add these variables in Easypanel. Replace the values in angle brackets:

```dotenv
EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN=https://mcp.example.com
EASYPANEL_MCP_ACCESS_TOKEN=<random-token>

EASYPANEL_URL=https://panel.example.com
EASYPANEL_TOKEN=<easypanel-api-token>
EASYPANEL_ALLOWED_PROJECTS=my-project
EASYPANEL_EXPECTED_VERSION=2.31.0
```

The image already sets `EASYPANEL_MCP_TRANSPORT=http`, binds to `0.0.0.0`, and
uses `readonly` mode. Keep the two tokens in Easypanel's secret fields. The
project allowlist must name the projects this MCP may see; `*` is not accepted.

### Where each value comes from

| Variable | What to enter | Where to get it |
| --- | --- | --- |
| `EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN` | `https://mcp.example.com` | Add a domain to this MCP service in Easypanel and copy the full HTTPS URL. |
| `EASYPANEL_MCP_ACCESS_TOKEN` | A random value, 32+ characters | Generate it in a password manager. Use the same value in your MCP client configuration. |
| `EASYPANEL_URL` | `https://panel.example.com` | The URL you use to open your Easypanel panel, without a path. |
| `EASYPANEL_TOKEN` | Your Easypanel API token | Easypanel **Settings → API → Generate Token**. Use the smallest scope available. |
| `EASYPANEL_ALLOWED_PROJECTS` | `my-project` | Copy the exact project name from the Easypanel sidebar. Separate multiple projects with commas. |
| `EASYPANEL_EXPECTED_VERSION` | For example, `2.31.0` | Copy the exact Easypanel version shown in the panel's version or update screen. |

The two tokens are different: `EASYPANEL_TOKEN` authenticates to Easypanel;
`EASYPANEL_MCP_ACCESS_TOKEN` authenticates MCP clients to this service.

### 3. Connect your agent

Copy this into the MCP configuration of your client:

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

### 4. Check it

```bash
curl -i https://mcp.example.com/healthz
```

`204` means the service is alive. Your agent should see exactly seven remote
tools: projects, services, service inspection, health, deployments, deployment
status, and sanitized logs.

## What it can do

Remote mode is deliberately read-only. It cannot deploy, apply, rotate secrets,
destroy services, execute shell commands, access the Docker socket, or act as a
general host administration API.

Local stdio mode also supports planning and guarded operations when you
explicitly need them on a trusted machine. The approval flow, audit log, and
full environment reference are documented in [`.env.example`](.env.example).

## Local development

```bash
git clone https://github.com/Yuhtin/easypanel-mcp.git && cd easypanel-mcp && npm ci && npm run build
```

Set `EASYPANEL_MCP_TRANSPORT=stdio` and the required Easypanel variables, then
run:

```bash
npm start
```

Run the checks before opening a pull request:

```bash
npm run check
```

## Security defaults

- Remote HTTP is always `readonly`.
- HTTPS, exact host validation, and a separate bearer token are required.
- Project access is an explicit allowlist.
- Responses redact environment values and credentials.
- Upstream calls, request sizes, sessions, and concurrency are bounded.

This is a preview release. Test it against a disposable Easypanel instance
before using it for production operations. See the [security model](docs/security-model.md)
and [security policy](SECURITY.md) for details.

## Links

- [Easypanel deployment details](deploy/easypanel/README.md)
- [Tool contract](docs/tool-contract.md)
- [Validation notes](docs/validation.md)
- [Contributing](CONTRIBUTING.md)
- [Release `v0.1.4`](https://github.com/Yuhtin/easypanel-mcp/releases/tag/v0.1.4)

## License

Apache-2.0. See [LICENSE](LICENSE).
