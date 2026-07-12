import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test, { type TestContext } from "node:test";

import { AdmissionGate } from "../src/core/admission-gate.js";
import { currentInvocationAbort } from "../src/core/invocation-abort.js";
import { SecretRegistry } from "../src/core/redaction.js";
import type { EasypanelOperator } from "../src/domain/operator.js";
import { RemoteMcpHttpServer } from "../src/remote/streamable-http-server.js";
import {
  createConfiguredRuntime,
  type ConfiguredRuntime,
} from "../src/runtime.js";
import { createEasypanelMcpServer } from "../src/server.js";

const ACCESS_TOKEN = "remote-access-token-0123456789abcdef";
const PANEL_TOKEN = "panel-token-that-must-never-be-serialized";
const PUBLIC_HOST = "mcp.example.test";

interface TestService {
  readonly port: number;
  readonly close: () => Promise<void>;
}

interface HttpResult {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

async function startService(
  t: TestContext,
  overrides: NodeJS.ProcessEnv = {},
): Promise<TestService> {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-http-"));
  const env: NodeJS.ProcessEnv = {
    EASYPANEL_FAKE_FIXTURE: resolve("fixtures/easypanel-2.31.json"),
    EASYPANEL_TOKEN: PANEL_TOKEN,
    EASYPANEL_ACCESS_MODE: "readonly",
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_AUDIT_PATH: join(directory, "audit.jsonl"),
    EASYPANEL_APPROVAL_DIR: join(directory, "approvals"),
    EASYPANEL_RUNTIME_LOCK_PATH: join(directory, "runtime.lock"),
    EASYPANEL_MCP_TRANSPORT: "http",
    EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: `https://${PUBLIC_HOST}`,
    EASYPANEL_MCP_HTTP_BIND_HOST: "127.0.0.1",
    EASYPANEL_MCP_HTTP_PORT: "3000",
    EASYPANEL_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
    ...overrides,
  };
  const runtime = await createConfiguredRuntime(env);
  const remote = await RemoteMcpHttpServer.start({ runtime, port: 0 });
  const address = remote.address;
  assert.ok(address);
  t.after(async () => {
    await remote.close();
    await runtime.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { port: address.port, close: async () => remote.close() };
}

function rpcHeaders(sessionId?: string): Record<string, string> {
  return {
    host: PUBLIC_HOST,
    authorization: `Bearer ${ACCESS_TOKEN}`,
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
    ...(sessionId
      ? {
          "mcp-session-id": sessionId,
          "mcp-protocol-version": "2025-11-25",
        }
      : {}),
  };
}

function send(
  port: number,
  options: {
    method?: "GET" | "POST" | "DELETE";
    path?: string;
    headers?: Record<string, string | string[]>;
    body?: string;
    chunks?: readonly string[];
  } = {},
): Promise<HttpResult> {
  return new Promise((resolvePromise, reject) => {
    const body = options.body;
    const headers = { ...(options.headers ?? {}) };
    if (body !== undefined && !options.chunks && headers["content-length"] === undefined) {
      headers["content-length"] = String(Buffer.byteLength(body, "utf8"));
    }
    const outgoing = request(
      {
        host: "127.0.0.1",
        port,
        method: options.method ?? "POST",
        path: options.path ?? "/mcp",
        headers,
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        incoming.on("error", reject);
        incoming.on("end", () => {
          resolvePromise({
            status: incoming.statusCode ?? 0,
            headers: incoming.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    outgoing.on("error", reject);
    if (options.chunks) {
      for (const chunk of options.chunks) outgoing.write(chunk, "utf8");
    } else if (body !== undefined) {
      outgoing.write(body, "utf8");
    }
    outgoing.end();
  });
}

function initializeBody(): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "offline-http-test", version: "1.0.0" },
    },
  });
}

test("remote HTTP is authenticated, stateful, JSON-only, and exposes the fixed tool registry", async (t) => {
  const service = await startService(t);
  const health = await send(service.port, { method: "GET", path: "/healthz" });
  assert.equal(health.status, 204);
  const initialized = await send(service.port, {
    headers: rpcHeaders(),
    body: initializeBody(),
  });
  assert.equal(initialized.status, 200);
  assert.equal(initialized.headers["cache-control"], "no-store");
  assert.equal(initialized.headers["access-control-allow-origin"], undefined);
  const sessionId = initialized.headers["mcp-session-id"];
  assert.equal(typeof sessionId, "string");
  assert.match(sessionId as string, /^[0-9a-f-]{36}$/);
  assert.equal((JSON.parse(initialized.body) as { result?: unknown }).result !== undefined, true);

  const beforeReady = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    }),
  });
  assert.equal(beforeReady.status, 409);

  const notification = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(notification.status, 202);

  const duplicateNotification = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(duplicateNotification.status, 409);

  const missingProtocol = await send(service.port, {
    headers: {
      host: PUBLIC_HOST,
      authorization: `Bearer ${ACCESS_TOKEN}`,
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-session-id": sessionId as string,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }),
  });
  assert.equal(missingProtocol.status, 400);

  const wrongProtocol = await send(service.port, {
    headers: {
      ...rpcHeaders(sessionId as string),
      "mcp-protocol-version": "2024-11-05",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }),
  });
  assert.equal(wrongProtocol.status, 400);

  const tools = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/list",
      params: {},
    }),
  });
  assert.equal(tools.status, 200);
  const listed = JSON.parse(tools.body) as { result: { tools: Array<{ name: string }> } };
  assert.deepEqual(
    listed.result.tools.map((tool) => tool.name).sort(),
    [
      "easypanel_check_service_health",
      "easypanel_get_deployment_status",
      "easypanel_get_sanitized_logs",
      "easypanel_inspect_service",
      "easypanel_list_deployments",
      "easypanel_list_projects",
      "easypanel_list_services",
    ],
  );

  const deniedCapabilities = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "easypanel_capabilities", arguments: {} },
    }),
  });
  assert.equal(deniedCapabilities.status, 403);

  const deniedPlan = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "easypanel_plan_service", arguments: {} },
    }),
  });
  assert.equal(deniedPlan.status, 403);

  const get = await send(service.port, {
    method: "GET",
    headers: { host: PUBLIC_HOST },
  });
  assert.equal(get.status, 405);

  const deleted = await send(service.port, {
    method: "DELETE",
    headers: {
      host: PUBLIC_HOST,
      authorization: `Bearer ${ACCESS_TOKEN}`,
      "mcp-session-id": sessionId as string,
      "mcp-protocol-version": "2025-11-25",
    },
  });
  assert.equal(deleted.status, 200);

  const afterDelete = await send(service.port, {
    headers: rpcHeaders(sessionId as string),
    body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/list", params: {} }),
  });
  assert.equal(afterDelete.status, 404);
});

test("remote HTTP rejects unauthenticated, spoofed, malformed and oversized input without reflection", async (t) => {
  const service = await startService(t);
  const canary = "never-reflect-this-user-controlled-secret";

  const withoutAuth = await send(service.port, {
    headers: {
      host: PUBLIC_HOST,
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    body: initializeBody(),
  });
  assert.equal(withoutAuth.status, 401);
  assert.equal(withoutAuth.headers.connection, "close");

  const wrongHost = await send(service.port, {
    headers: { ...rpcHeaders(), host: "attacker.example.test" },
    body: initializeBody(),
  });
  assert.equal(wrongHost.status, 404);

  const wrongOrigin = await send(service.port, {
    headers: { ...rpcHeaders(), origin: "https://attacker.example.test" },
    body: initializeBody(),
  });
  assert.equal(wrongOrigin.status, 404);

  const duplicateAuth = await send(service.port, {
    headers: {
      ...rpcHeaders(),
      authorization: [`Bearer ${ACCESS_TOKEN}`, `Bearer ${ACCESS_TOKEN}`],
    },
    body: initializeBody(),
  });
  assert.equal(duplicateAuth.status, 401);

  const invalid = await send(service.port, {
    headers: rpcHeaders(),
    body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":"${canary}"}`,
  });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.body.includes(canary), false);
  assert.equal(invalid.body.includes(ACCESS_TOKEN), false);
  assert.equal(invalid.body.includes(PANEL_TOKEN), false);

  const oversized = await send(service.port, {
    headers: rpcHeaders(),
    chunks: ["{" + `"padding":"${"x".repeat(131_080)}` + "}"],
  });
  assert.equal(oversized.status, 413);

  const query = await send(service.port, {
    path: "/mcp?token=must-not-be-accepted",
    headers: rpcHeaders(),
    body: initializeBody(),
  });
  assert.equal(query.status, 404);

  for (const path of [
    "/x/../mcp",
    "/%6dcp",
    "/mcp#fragment",
    "http://attacker.example.test/mcp",
  ]) {
    const rejected = await send(service.port, {
      path,
      headers: rpcHeaders(),
      body: initializeBody(),
    });
    assert.equal(rejected.status, 404, path);
  }

  const expect = await send(service.port, {
    headers: { ...rpcHeaders(), expect: "100-continue" },
  });
  assert.equal(expect.status, 417);

  const healthWithBody = await send(service.port, {
    method: "GET",
    path: "/healthz",
    headers: { "content-length": "1" },
    body: "x",
  });
  assert.equal(healthWithBody.status, 405);

  const exact = await send(service.port, {
    headers: rpcHeaders(),
    body: jsonBodyWithBytes(131_072),
  });
  assert.equal(exact.status, 400);
  const over = await send(service.port, {
    headers: rpcHeaders(),
    body: jsonBodyWithBytes(131_073),
  });
  assert.equal(over.status, 413);

});

test("remote HTTP reserves session capacity before async initialization", async (t) => {
  const service = await startService(t, { EASYPANEL_MCP_HTTP_MAX_SESSIONS: "1" });
  const outcomes = await Promise.all(
    Array.from({ length: 4 }, () =>
      send(service.port, { headers: rpcHeaders(), body: initializeBody() }),
    ),
  );
  assert.equal(outcomes.filter((result) => result.status === 200).length, 1);
  assert.equal(outcomes.filter((result) => result.status === 503).length, 3);
});

test("remote deadline aborts the handler before draining its session", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-http-timeout-"));
  const env: NodeJS.ProcessEnv = {
    EASYPANEL_FAKE_FIXTURE: resolve("fixtures/easypanel-2.31.json"),
    EASYPANEL_TOKEN: PANEL_TOKEN,
    EASYPANEL_ACCESS_MODE: "readonly",
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_AUDIT_PATH: join(directory, "audit.jsonl"),
    EASYPANEL_APPROVAL_DIR: join(directory, "approvals"),
    EASYPANEL_RUNTIME_LOCK_PATH: join(directory, "runtime.lock"),
    EASYPANEL_MCP_TRANSPORT: "http",
    EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: `https://${PUBLIC_HOST}`,
    EASYPANEL_MCP_HTTP_BIND_HOST: "127.0.0.1",
    EASYPANEL_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
    EASYPANEL_MCP_HTTP_MAX_SESSIONS: "1",
  };
  const base = await createConfiguredRuntime(env);
  let settled = false;
  let fatal: Error | undefined;
  let calls = 0;
  let resolveSettled: (() => void) | undefined;
  const handlerSettled = new Promise<void>((resolvePromise) => {
    resolveSettled = resolvePromise;
  });
  const registry = new SecretRegistry();
  const admission = new AdmissionGate(1);
  const operator = {
    async listProjects() {
      calls += 1;
      if (calls === 1) {
        const signal = currentInvocationAbort();
        assert.ok(signal instanceof AbortSignal);
        await new Promise<void>((resolvePromise) => {
          if (signal.aborted) resolvePromise();
          else signal.addEventListener("abort", () => resolvePromise(), { once: true });
        });
      }
      settled = true;
      resolveSettled?.();
      return { projects: [] };
    },
  } as unknown as EasypanelOperator;
  const runtime: ConfiguredRuntime = {
    config: base.config,
    createMcpServer() {
      return createEasypanelMcpServer(operator, registry, { admission });
    },
    verifyRemoteAccessToken(candidate: string) {
      return base.verifyRemoteAccessToken(candidate);
    },
    close: async () => base.close(),
  };
  const remote = await RemoteMcpHttpServer.start({
    runtime,
    port: 0,
    requestDeadlineMs: 25,
    onFatal(error) {
      fatal = error;
    },
  });
  const address = remote.address;
  assert.ok(address);
  t.after(async () => {
    await remote.close();
    await base.close();
    await rm(directory, { recursive: true, force: true });
  });

  const initialized = await send(address.port, {
    headers: rpcHeaders(),
    body: initializeBody(),
  });
  assert.equal(initialized.status, 200);
  const sessionId = initialized.headers["mcp-session-id"] as string;
  const ready = await send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(ready.status, 202);

  const timedOut = await send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "easypanel_list_projects", arguments: {} },
    }),
  });
  assert.equal(timedOut.status, 504);
  await Promise.race([
    handlerSettled,
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error("handler did not observe deadline abort")), 1_000);
    }),
  ]);
  assert.equal(settled, true);

  let fresh: HttpResult | undefined;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    fresh = await send(address.port, { headers: rpcHeaders(), body: initializeBody() });
    if (fresh.status === 200) break;
    assert.equal(fresh.status, 503);
    await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 10));
  }
  assert.equal(fresh?.status, 200);
  const freshSessionId = fresh?.headers["mcp-session-id"] as string;
  const freshReady = await send(address.port, {
    headers: rpcHeaders(freshSessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(freshReady.status, 202);
  const reusedAdmission = await send(address.port, {
    headers: rpcHeaders(freshSessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "easypanel_list_projects", arguments: {} },
    }),
  });
  assert.equal(reusedAdmission.status, 200);
  assert.equal(reusedAdmission.body.includes("SERVER_BUSY"), false);
  assert.equal(reusedAdmission.body.includes("UPSTREAM_TIMEOUT"), false);
  assert.equal(calls, 2);
  assert.equal(fatal, undefined);
});

test("a noncooperative remote handler triggers fail-closed termination", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-http-fatal-"));
  const env: NodeJS.ProcessEnv = {
    EASYPANEL_FAKE_FIXTURE: resolve("fixtures/easypanel-2.31.json"),
    EASYPANEL_TOKEN: PANEL_TOKEN,
    EASYPANEL_ACCESS_MODE: "readonly",
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_AUDIT_PATH: join(directory, "audit.jsonl"),
    EASYPANEL_APPROVAL_DIR: join(directory, "approvals"),
    EASYPANEL_RUNTIME_LOCK_PATH: join(directory, "runtime.lock"),
    EASYPANEL_MCP_TRANSPORT: "http",
    EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: `https://${PUBLIC_HOST}`,
    EASYPANEL_MCP_HTTP_BIND_HOST: "127.0.0.1",
    EASYPANEL_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
  };
  const base = await createConfiguredRuntime(env);
  const registry = new SecretRegistry();
  const operator = {
    async listProjects() {
      return await new Promise<{ projects: string[] }>(() => undefined);
    },
  } as unknown as EasypanelOperator;
  let resolveFatal: ((error: Error) => void) | undefined;
  const fatal = new Promise<Error>((resolvePromise) => {
    resolveFatal = resolvePromise;
  });
  const runtime: ConfiguredRuntime = {
    config: base.config,
    createMcpServer() {
      return createEasypanelMcpServer(operator, registry, {
        admission: new AdmissionGate(1),
      });
    },
    verifyRemoteAccessToken(candidate: string) {
      return base.verifyRemoteAccessToken(candidate);
    },
    close: async () => base.close(),
  };
  const remote = await RemoteMcpHttpServer.start({
    runtime,
    port: 0,
    requestDeadlineMs: 25,
    abortSettlementGraceMs: 25,
    onFatal(error) {
      resolveFatal?.(error);
    },
  });
  const address = remote.address;
  assert.ok(address);
  t.after(async () => {
    await remote.close();
    await base.close();
    await rm(directory, { recursive: true, force: true });
  });

  const initialized = await send(address.port, {
    headers: rpcHeaders(),
    body: initializeBody(),
  });
  const sessionId = initialized.headers["mcp-session-id"] as string;
  const ready = await send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(ready.status, 202);
  const timedOut = await send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "easypanel_list_projects", arguments: {} },
    }),
  });
  assert.equal(timedOut.status, 504);
  const fatalError = await Promise.race([
    fatal,
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error("noncooperative handler did not terminate")), 1_000);
    }),
  ]);
  assert.equal(fatalError.message, "REMOTE_REQUEST_DID_NOT_SETTLE");
});

test("remote close aborts and drains an active tool before closing its transport", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-http-close-"));
  const env: NodeJS.ProcessEnv = {
    EASYPANEL_FAKE_FIXTURE: resolve("fixtures/easypanel-2.31.json"),
    EASYPANEL_TOKEN: PANEL_TOKEN,
    EASYPANEL_ACCESS_MODE: "readonly",
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_AUDIT_PATH: join(directory, "audit.jsonl"),
    EASYPANEL_APPROVAL_DIR: join(directory, "approvals"),
    EASYPANEL_RUNTIME_LOCK_PATH: join(directory, "runtime.lock"),
    EASYPANEL_MCP_TRANSPORT: "http",
    EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: `https://${PUBLIC_HOST}`,
    EASYPANEL_MCP_HTTP_BIND_HOST: "127.0.0.1",
    EASYPANEL_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
  };
  const base = await createConfiguredRuntime(env);
  const registry = new SecretRegistry();
  let resolveStarted: (() => void) | undefined;
  const started = new Promise<void>((resolvePromise) => {
    resolveStarted = resolvePromise;
  });
  let aborted = false;
  const operator = {
    async listProjects() {
      const signal = currentInvocationAbort();
      assert.ok(signal instanceof AbortSignal);
      resolveStarted?.();
      await new Promise<void>((resolvePromise) => {
        if (signal.aborted) resolvePromise();
        else signal.addEventListener("abort", () => resolvePromise(), { once: true });
      });
      aborted = true;
      return { projects: [] };
    },
  } as unknown as EasypanelOperator;
  const runtime: ConfiguredRuntime = {
    config: base.config,
    createMcpServer() {
      return createEasypanelMcpServer(operator, registry, {
        admission: new AdmissionGate(1),
      });
    },
    verifyRemoteAccessToken(candidate: string) {
      return base.verifyRemoteAccessToken(candidate);
    },
    close: async () => base.close(),
  };
  const remote = await RemoteMcpHttpServer.start({
    runtime,
    port: 0,
    requestDeadlineMs: 1_000,
    onFatal(error) {
      throw error;
    },
  });
  const address = remote.address;
  assert.ok(address);
  t.after(async () => {
    await remote.close();
    await base.close();
    await rm(directory, { recursive: true, force: true });
  });

  const initialized = await send(address.port, {
    headers: rpcHeaders(),
    body: initializeBody(),
  });
  const sessionId = initialized.headers["mcp-session-id"] as string;
  const ready = await send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  });
  assert.equal(ready.status, 202);
  const inFlight = send(address.port, {
    headers: rpcHeaders(sessionId),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "easypanel_list_projects", arguments: {} },
    }),
  });
  await started;
  await remote.close();
  const result = await inFlight;
  assert.equal(result.status, 504);
  assert.equal(aborted, true);
});

test("remote HTTP configuration fails closed unless it remains readonly and fully configured", async () => {
  const base: NodeJS.ProcessEnv = {
    EASYPANEL_FAKE_FIXTURE: resolve("fixtures/easypanel-2.31.json"),
    EASYPANEL_ACCESS_MODE: "readonly",
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_MCP_TRANSPORT: "http",
    EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: `https://${PUBLIC_HOST}`,
    EASYPANEL_MCP_ACCESS_TOKEN: ACCESS_TOKEN,
  };
  const runtime = await createConfiguredRuntime(base);
  await runtime.close();
  await assert.rejects(
    createConfiguredRuntime({ ...base, EASYPANEL_ACCESS_MODE: "operator" }),
  );
  await assert.rejects(
    createConfiguredRuntime({ ...base, EASYPANEL_MCP_ACCESS_TOKEN: "short" }),
  );
  await assert.rejects(
    createConfiguredRuntime({ ...base, EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN: "http://mcp.example.test" }),
  );
  await assert.rejects(
    createConfiguredRuntime({
      ...base,
      EASYPANEL_TIMEOUT_MS: "1000",
      EASYPANEL_MCP_HTTP_REQUEST_TIMEOUT_MS: "10999",
    }),
  );
  await assert.rejects(
    createConfiguredRuntime({ ...base, EASYPANEL_TIMEOUT_MS: "10001" }),
  );
});

function jsonBodyWithBytes(bytes: number): string {
  const prefix = '{"padding":"';
  const suffix = '"}';
  const padding = bytes - Buffer.byteLength(prefix + suffix, "utf8");
  assert.ok(padding >= 0);
  const body = `${prefix}${"x".repeat(padding)}${suffix}`;
  assert.equal(Buffer.byteLength(body, "utf8"), bytes);
  return body;
}
