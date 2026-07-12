# Contributing

Thanks for helping improve `easypanel-mcp`.

## Before opening a pull request

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Tests must use the bundled fake fixture or mocked HTTP responses. Do not add a
real panel URL, credential, deployment identifier, or private environment value
to source, fixtures, logs, or tests.

Security-sensitive changes should include a regression test and explain the
boundary being preserved. In particular, do not add shell execution, raw RPC,
arbitrary URL fetching, secret-value output, or a remote mutation route without a
new security design and review.

## Pull requests

- Keep changes focused and document user-visible behavior.
- Update the README or deployment guide when configuration changes.
- Preserve exact version pins and run `npm audit` for dependency changes.
- Do not commit `node_modules`, `dist`, `.test-dist`, `.state`, `.env`, or tokens.
