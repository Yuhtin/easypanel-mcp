# Validation

The repository's automated checks are offline. They use the bundled fixture and
mocked `fetch` implementations; no Easypanel URL or credential is contacted.

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The test suite covers:

- fake gateway schema validation, projections, mutation acknowledgements, and
  defensive snapshots;
- HTTPS/origin, redirect, timeout, response-size, and upstream-body handling;
- MCP stdio framing and Streamable HTTP lifecycle/authentication;
- exact seven-tool remote filtering and pre-SDK mutation denial;
- cancellation propagation, admission reuse after timeout, shutdown draining,
  and fail-closed behavior for a non-cooperative handler;
- policy, plan, approval, redaction, audit, lock, and private-path invariants.

Before calling a deployment production-ready, validate the pinned
`EASYPANEL_EXPECTED_VERSION` against a disposable panel with no sensitive data.
That test is intentionally not part of CI and requires an operator to provide a
safe test instance and credentials.
