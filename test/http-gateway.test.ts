import assert from "node:assert/strict";
import test from "node:test";

import { runWithInvocationAbort } from "../src/core/invocation-abort.js";
import { SecretRegistry } from "../src/core/redaction.js";
import {
  GatewayError,
  HttpEasypanelGateway,
  parseOpenApiProcedures,
} from "../src/gateway/http-gateway.js";
import { PROCEDURES, resolveProcedures } from "../src/gateway/procedures.js";

const PANEL_TOKEN = "panel-token-that-must-not-escape-123456789";

function gateway(
  fetch: typeof globalThis.fetch,
  options: {
    baseUrl?: string;
    apiFlavor?: "auto" | "rpc" | "trpc";
    expectedVersion?: string;
    timeoutMs?: number;
    maxResponseBytes?: number;
  } = {},
): HttpEasypanelGateway {
  return new HttpEasypanelGateway({
    baseUrl: new URL(options.baseUrl ?? "https://panel.example.test"),
    token: PANEL_TOKEN,
    instanceLabel: "offline-test",
    apiFlavor: options.apiFlavor ?? "rpc",
    expectedVersion: options.expectedVersion ?? "2.31.0",
    timeoutMs: options.timeoutMs ?? 1_000,
    maxResponseBytes: options.maxResponseBytes ?? 64 * 1024,
    secrets: new SecretRegistry(),
    fetch,
  });
}

function expectCode(code: string, forbidden: readonly string[] = []) {
  return (error: unknown): boolean => {
    assert.equal(
      Boolean(error && typeof error === "object" && "code" in error && error.code === code),
      true,
    );
    const rendered = `${error instanceof Error ? `${error.name}:${error.message}` : String(error)} ${JSON.stringify(error)}`;
    for (const value of forbidden) assert.equal(rendered.includes(value), false);
    return true;
  };
}

test("HTTP gateway rejects non-HTTPS origins before invoking fetch", () => {
  let called = false;
  const fetch: typeof globalThis.fetch = async () => {
    called = true;
    throw new Error("must not be called");
  };

  assert.throws(
    () => gateway(fetch, { baseUrl: "http://panel.example.test" }),
    expectCode("INVALID_INSTANCE_URL"),
  );
  assert.equal(called, false);
});

test("HTTP gateway sets redirect:error and masks redirect failures that contain secrets", async () => {
  const upstreamSecret = "redirect-body-secret-value";
  let calls = 0;
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    calls += 1;
    assert.equal(init?.redirect, "error");
    assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${PANEL_TOKEN}`);
    throw new TypeError(
      `redirect refused: https://evil.example.test/?token=${PANEL_TOKEN}&body=${upstreamSecret}`,
    );
  };

  await assert.rejects(
    gateway(fetch).discover(),
    expectCode("UPSTREAM_UNAVAILABLE", [PANEL_TOKEN, upstreamSecret, "evil.example.test"]),
  );
  assert.equal(calls, 2);
});

test("HTTP gateway never surfaces an upstream error body or bearer token", async () => {
  const bodySecret = "secret-returned-by-upstream-error";
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    assert.equal(init?.redirect, "error");
    return new Response(
      JSON.stringify({
        error: {
          message: `authorization=Bearer ${PANEL_TOKEN}`,
          databasePassword: bodySecret,
        },
      }),
      { status: 401, headers: { "content-type": "application/json" } },
    );
  };

  await assert.rejects(
    gateway(fetch).discover(),
    expectCode("UPSTREAM_HTTP_401", [PANEL_TOKEN, bodySecret, "databasePassword"]),
  );
});

test("HTTP gateway never waits for rejected-response body cancellation", async () => {
  const fetch: typeof globalThis.fetch = async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("untrusted error body"));
        },
        cancel() {
          return new Promise<void>(() => undefined);
        },
      }),
      { status: 401, headers: { "content-type": "application/json" } },
    );

  await assert.rejects(
    gateway(fetch).discover(),
    expectCode("UPSTREAM_HTTP_401", [PANEL_TOKEN]),
  );
});

test("HTTP gateway attaches an abort timeout to each fake fetch attempt", async () => {
  const signals: AbortSignal[] = [];
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    const signal = init?.signal;
    assert.ok(signal instanceof AbortSignal);
    signals.push(signal);
    return await new Promise<Response>((_resolve, reject) => {
      const rejectForAbort = () => reject(signal.reason ?? new Error("aborted"));
      if (signal.aborted) rejectForAbort();
      else signal.addEventListener("abort", rejectForAbort, { once: true });
    });
  };

  await assert.rejects(
    gateway(fetch, { timeoutMs: 1_000 }).discover(),
    expectCode("UPSTREAM_TIMEOUT", [PANEL_TOKEN]),
  );
  assert.equal(signals.length, 2);
  assert.equal(signals.every((signal) => signal.aborted), true);
});

test("HTTP gateway settles a remote invocation deadline without retrying", async () => {
  let calls = 0;
  let sawAbort = false;
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    calls += 1;
    const signal = init?.signal;
    assert.ok(signal instanceof AbortSignal);
    return await new Promise<Response>((_resolve, reject) => {
      const rejectForAbort = () => {
        sawAbort = true;
        reject(signal.reason ?? new Error("aborted"));
      };
      if (signal.aborted) rejectForAbort();
      else signal.addEventListener("abort", rejectForAbort, { once: true });
    });
  };
  const deadline = new AbortController();
  const operation = runWithInvocationAbort(deadline.signal, () => gateway(fetch).discover());

  await new Promise<void>((resolve) => setImmediate(resolve));
  deadline.abort();

  await assert.rejects(operation, expectCode("UPSTREAM_TIMEOUT", [PANEL_TOKEN]));
  assert.equal(calls, 1);
  assert.equal(sawAbort, true);
});

test("HTTP gateway times out a body that stalls after response headers", async () => {
  let stalledAttempts = 0;
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths: procedurePaths() }));
    }
    if (path === "/api/rpc/update/getStatus") {
      stalledAttempts += 1;
      return new Response(
        new ReadableStream<Uint8Array>({
          pull() {
            return new Promise<void>(() => undefined);
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error("unexpected fake request");
  };

  await assert.rejects(
    gateway(fetch, { timeoutMs: 1_000 }).discover(),
    expectCode("UPSTREAM_TIMEOUT", [PANEL_TOKEN]),
  );
  assert.equal(stalledAttempts, 2);
});

test("HTTP gateway rejects both declared and actual bodies above the response limit", async (t) => {
  await t.test("declared content length", async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response("{}", {
        status: 200,
        headers: { "content-length": "4096", "content-type": "application/json" },
      });

    await assert.rejects(
      gateway(fetch, { maxResponseBytes: 1_024 }).discover(),
      expectCode("RESPONSE_TOO_LARGE", [PANEL_TOKEN]),
    );
  });

  await t.test("actual body length", async () => {
    const fetch: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ padding: "x".repeat(2_048) }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    await assert.rejects(
      gateway(fetch, { maxResponseBytes: 1_024 }).discover(),
      expectCode("RESPONSE_TOO_LARGE", [PANEL_TOKEN]),
    );
  });

  for (const chunkBytes of [0, 1]) {
    await t.test(`${chunkBytes}-byte chunk flood`, async () => {
      let pulls = 0;
      let cancelled = false;
      const fetch: typeof globalThis.fetch = async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              pulls += 1;
              controller.enqueue(new Uint8Array(chunkBytes));
            },
            cancel() {
              cancelled = true;
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );

      await assert.rejects(
        gateway(fetch).discover(),
        expectCode("RESPONSE_TOO_LARGE", [PANEL_TOKEN]),
      );
      assert.equal(pulls > 4_096 && pulls < 4_112, true);
      assert.equal(cancelled, true);
    });
  }

  await t.test("never waits for an oversized body cancellation", async () => {
    const fetch: typeof globalThis.fetch = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/api/openapi.json") {
        return new Response(JSON.stringify({ paths: procedurePaths() }));
      }
      if (path === "/api/rpc/update/getStatus") {
        return new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              controller.enqueue(new Uint8Array(2_048));
            },
            cancel() {
              return new Promise<void>(() => undefined);
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error("unexpected fake request");
    };

    await assert.rejects(
      gateway(fetch, { maxResponseBytes: 1_024 }).discover(),
      expectCode("RESPONSE_TOO_LARGE", [PANEL_TOKEN]),
    );
  });
});

test("OpenAPI discovery confirms only compiled procedures with the expected method", () => {
  const available = parseOpenApiProcedures({
    paths: {
      "/api/rpc/projects/listProjectsAndServices": { get: {} },
      "/api/rpc/services/app/destroyService": { get: {} },
      "/api/rpc/evil/dumpSecrets": { post: {} },
      "/outside/rpc/projects/createProject": { post: {} },
    },
  });

  assert.equal(available.get("projects.listProjectsAndServices"), "query");
  assert.equal(available.get("services.app.destroyService"), "query");
  assert.equal(available.get("evil.dumpSecrets"), "mutation");
  assert.equal(available.has("projects.createProject"), false);

  const relaxed = resolveProcedures(available, false);
  assert.equal(relaxed.features.has("inventory"), true);
  assert.equal(relaxed.features.has("destroy_app"), false);
  assert.equal(relaxed.byName.has("evil.dumpSecrets"), false);

  assert.throws(
    () => resolveProcedures(available, true),
    expectCode("INCOMPATIBLE_CAPABILITIES"),
  );

  const tooManyPaths: Record<string, unknown> = {};
  for (let index = 0; index < 2_001; index += 1) {
    tooManyPaths[`/outside/${index}`] = { get: {} };
  }
  assert.throws(
    () => parseOpenApiProcedures({ paths: tooManyPaths }),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
});

test("sensitive-field scanning rejects wide arrays and objects before breadth allocation", async () => {
  const wideValues: unknown[] = [
    Array.from({ length: 10_001 }, () => null),
    Object.fromEntries(
      Array.from({ length: 10_001 }, (_, index) => [`field_${index}`, null]),
    ),
  ];

  for (const wide of wideValues) {
    const fetch: typeof globalThis.fetch = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/api/openapi.json") {
        return new Response(JSON.stringify({ paths: procedurePaths() }));
      }
      if (path === "/api/rpc/update/getStatus") {
        return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
      }
      if (path === "/api/rpc/projects/listProjectsAndServices") {
        return new Response(JSON.stringify({
          json: { projects: [], services: [], untrustedWideValue: wide },
        }));
      }
      throw new Error("unexpected fake request");
    };
    await assert.rejects(
      gateway(fetch, { maxResponseBytes: 512 * 1_024 }).listInventory(),
      expectCode("INVALID_UPSTREAM_RESPONSE"),
    );
  }
});

test("sensitive-field scanning accepts the largest minimal contract-valid inventory", async () => {
  const projects = Array.from({ length: 1_000 }, (_, index) => ({
    name: `project-${index}`,
  }));
  const services = Array.from({ length: 10_000 }, (_, index) => ({
    projectName: "project-0",
    name: `service-${index}`,
    type: "app",
    enabled: true,
  }));
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths: procedurePaths() }));
    }
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
    }
    if (path === "/api/rpc/projects/listProjectsAndServices") {
      return new Response(JSON.stringify({ json: { projects, services } }));
    }
    throw new Error("unexpected fake request");
  };

  const inventory = await gateway(fetch, {
    maxResponseBytes: 2 * 1_024 * 1_024,
  }).listInventory();
  assert.equal(inventory.projects.length, 1_000);
  assert.equal(inventory.services.length, 10_000);
});

test("HTTP discovery fails closed before use when OpenAPI omits required procedures", async () => {
  let calls = 0;
  const fetch: typeof globalThis.fetch = async () => {
    calls += 1;
    return new Response(
      JSON.stringify({
        info: { version: "2.31.0" },
        paths: {
          "/api/rpc/projects/listProjectsAndServices": { get: {} },
          "/api/rpc/evil/dumpSecrets": { post: {} },
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  await assert.rejects(
    gateway(fetch).discover(),
    expectCode("INCOMPATIBLE_CAPABILITIES", [PANEL_TOKEN]),
  );
  assert.equal(calls, 1);
});

test("HTTP discovery rejects a panel version different from the mandatory exact pin", async () => {
  const paths = Object.fromEntries(
    Object.values(PROCEDURES).map((definition) => {
      const candidate = definition.candidates[0] as string;
      return [
        `/api/rpc/${candidate.split(".").join("/")}`,
        { [definition.type === "query" ? "get" : "post"]: {} },
      ];
    }),
  );
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") return new Response(JSON.stringify({ paths }));
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.1" } }));
    }
    throw new Error("unexpected fake request");
  };

  await assert.rejects(
    gateway(fetch, { expectedVersion: "2.31.0" }).discover(),
    expectCode("VERSION_MISMATCH", [PANEL_TOKEN]),
  );
});

test("RPC uses POST on the wire while OpenAPI GET remains the query security class", async () => {
  const paths = procedurePaths();
  const seen: string[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    seen.push(`${init?.method ?? "GET"} ${url.pathname}`);
    if (url.pathname === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths }), { status: 200 });
    }
    assert.equal(init?.method, "POST");
    if (url.pathname === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }), { status: 200 });
    }
    if (url.pathname === "/api/rpc/projects/listProjectsAndServices") {
      return new Response(JSON.stringify({ json: { projects: [], services: [] } }), {
        status: 200,
      });
    }
    throw new Error("unexpected fake request");
  };

  assert.deepEqual(await gateway(fetch).listInventory(), { projects: [], services: [] });
  assert.equal(
    seen.includes("POST /api/rpc/projects/listProjectsAndServices"),
    true,
  );
});

test("mutation acknowledgements with explicit false fail closed", async () => {
  const paths = procedurePaths();
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") return new Response(JSON.stringify({ paths }));
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
    }
    if (path === "/api/rpc/projects/createProject") {
      return new Response(JSON.stringify({ json: { success: false, name: "sandbox" } }));
    }
    throw new Error("unexpected fake request");
  };

  await assert.rejects(
    gateway(fetch).createProject("sandbox", { auditId: "audit-test" }),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
});

test("HTTP mutations require explicit success and an exact returned target", async (t) => {
  for (const [label, acknowledgement] of [
    ["null", null],
    ["boolean", true],
    ["targetless", { success: true }],
    ["wrong target", { success: true, name: "different" }],
  ] as const) {
    await t.test(label, async () => {
      const fetch = rpcMutationFetch(
        "/api/rpc/projects/createProject",
        acknowledgement,
      );
      await assert.rejects(
        gateway(fetch).createProject("sandbox", { auditId: "audit-test" }),
        expectCode(
          label === "wrong target"
            ? "UPSTREAM_TARGET_MISMATCH"
            : "INVALID_UPSTREAM_RESPONSE",
        ),
      );
    });
  }

  await gateway(
    rpcMutationFetch("/api/rpc/projects/createProject", {
      success: true,
      name: "sandbox",
    }),
  ).createProject("sandbox", { auditId: "audit-test" });
});

test("legacy configuration mutations accept Easypanel's undefined acknowledgement", async () => {
  const fetch = rpcMutationFetch(
    "/api/rpc/services/app/updateEnv",
    null,
  );
  await gateway(fetch).updateEnvironment(
    "sandbox",
    "api",
    "MCP_MODE=readonly",
    { auditId: "audit-test" },
  );
});

test("database creation requires a target-bound credential acknowledgement", async () => {
  const fetch = rpcMutationFetch("/api/rpc/services/postgres/createService", {
    success: true,
    projectName: "sandbox",
    serviceName: "database",
    type: "postgres",
  });
  await assert.rejects(
    gateway(fetch).createService(
      "sandbox",
      "database",
      "postgres",
      { password: "bootstrap-password-secret" },
      { auditId: "audit-test" },
    ),
    expectCode("INVALID_UPSTREAM_RESPONSE", ["bootstrap-password-secret"]),
  );
});

test("deploy acknowledgement and detail require exact request, type, and target correlation", async () => {
  const deploymentId = "deployment-action-1";
  let mutationIncludesType = true;
  let detailIncludesType = true;
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths: procedurePaths() }));
    }
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
    }
    if (path === "/api/rpc/services/app/deployService") {
      return new Response(JSON.stringify({
        json: {
          success: true,
          id: deploymentId,
          ...(mutationIncludesType ? { type: "deployment" } : {}),
          projectName: "sandbox",
          serviceName: "api",
          clientRequestId: "audit-test",
        },
      }));
    }
    if (path === "/api/rpc/actions/getAction") {
      return new Response(JSON.stringify({
        json: {
          id: deploymentId,
          ...(detailIncludesType ? { type: "deployment" } : {}),
          projectName: "sandbox",
          serviceName: "api",
          clientRequestId: "audit-test",
          status: "success",
          createdAt: "2026-07-11T12:00:00.000Z",
          finishedAt: "2026-07-11T12:00:01.000Z",
        },
      }));
    }
    throw new Error("unexpected fake request");
  };

  const client = gateway(fetch);
  assert.equal(
    await client.deployService("sandbox", "api", { auditId: "audit-test" }),
    deploymentId,
  );
  mutationIncludesType = false;
  await assert.rejects(
    client.deployService("sandbox", "api", { auditId: "audit-test" }),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
  mutationIncludesType = true;
  assert.equal(
    (
      await client.getDeploymentForRequest(
        deploymentId,
        "sandbox",
        "api",
        "audit-test",
      )
    )?.status,
    "running",
  );
  detailIncludesType = false;
  await assert.rejects(
    client.getDeploymentForRequest(
      deploymentId,
      "sandbox",
      "api",
      "audit-test",
    ),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
  detailIncludesType = true;
  await assert.rejects(
    client.getDeploymentForRequest(
      deploymentId,
      "sandbox",
      "api",
      "different-request",
    ),
    expectCode("UPSTREAM_TARGET_MISMATCH"),
  );
});

test("lifecycle mutations return and verify one exact target-bound action id", async () => {
  const actionId = "lifecycle-action-1";
  let mutationIncludesType = true;
  let detailIncludesType = true;
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths: procedurePaths() }));
    }
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
    }
    if (path === "/api/rpc/services/app/restartService") {
      return new Response(JSON.stringify({
        json: {
          success: true,
          id: actionId,
          ...(mutationIncludesType ? { type: "lifecycle" } : {}),
          projectName: "sandbox",
          serviceName: "api",
          operation: "restart",
          clientRequestId: "audit-test",
        },
      }));
    }
    if (path === "/api/rpc/actions/listActions") {
      return new Response(JSON.stringify({
        json: {
          items: [{
            id: "previous-lifecycle-action",
            type: "lifecycle",
            projectName: "sandbox",
            serviceName: "api",
            operation: "restart",
            status: "success",
          }],
          total: 1,
          hasMore: false,
        },
      }));
    }
    if (path === "/api/rpc/actions/getAction") {
      return new Response(JSON.stringify({
        json: {
          id: actionId,
          ...(detailIncludesType ? { type: "lifecycle" } : {}),
          projectName: "sandbox",
          serviceName: "api",
          operation: "restart",
          clientRequestId: "audit-test",
          status: "success",
        },
      }));
    }
    throw new Error("unexpected fake request");
  };

  const client = gateway(fetch);
  assert.deepEqual(await client.listLifecycleActions("sandbox", "api"), [{
    id: "previous-lifecycle-action",
    project: "sandbox",
    service: "api",
    operation: "restart",
    status: "succeeded",
  }]);
  assert.equal(
    await client.restartService("sandbox", "api", { auditId: "audit-test" }),
    actionId,
  );
  mutationIncludesType = false;
  await assert.rejects(
    client.restartService("sandbox", "api", { auditId: "audit-test" }),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
  mutationIncludesType = true;
  assert.equal(
    await client.getLifecycleActionStatus(
      actionId,
      "sandbox",
      "api",
      "restart",
      "audit-test",
    ),
    "succeeded",
  );
  detailIncludesType = false;
  await assert.rejects(
    client.getLifecycleActionStatus(
      actionId,
      "sandbox",
      "api",
      "restart",
      "audit-test",
    ),
    expectCode("INVALID_UPSTREAM_RESPONSE"),
  );
  detailIncludesType = true;
  await assert.rejects(
    client.getLifecycleActionStatus(
      actionId,
      "sandbox",
      "api",
      "restart",
      "different-request",
    ),
    expectCode("UPSTREAM_TARGET_MISMATCH"),
  );
});

test("lifecycle history requires an explicitly complete, non-truncated page", async () => {
  const responses: unknown[] = [
    [{ id: "legacy-array" }],
    { items: [], total: 1, hasMore: true },
    { items: [], total: 1, hasMore: false },
  ];

  for (const response of responses) {
    const fetch: typeof globalThis.fetch = async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/api/openapi.json") {
        return new Response(JSON.stringify({ paths: procedurePaths() }));
      }
      if (path === "/api/rpc/update/getStatus") {
        return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
      }
      if (path === "/api/rpc/actions/listActions") {
        return new Response(JSON.stringify({ json: response }));
      }
      throw new Error("unexpected fake request");
    };
    await assert.rejects(
      gateway(fetch).listLifecycleActions("sandbox", "api"),
      expectCode("INVALID_UPSTREAM_RESPONSE"),
    );
  }
});

test("service absence requires project inventory and project inspection to agree", async (t) => {
  const makeFetch = (
    inventory: { projects: unknown[]; services: unknown[] },
    inspection: Response,
  ): typeof globalThis.fetch =>
    async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === "/api/openapi.json") {
        return new Response(JSON.stringify({ paths: procedurePaths() }));
      }
      if (path === "/api/rpc/update/getStatus") {
        return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
      }
      if (path === "/api/rpc/projects/listProjectsAndServices") {
        return new Response(JSON.stringify({ json: inventory }));
      }
      if (path === "/api/rpc/projects/inspectProject") return inspection.clone();
      throw new Error("unexpected fake request");
    };

  await t.test("inventory project plus inspection 404", async () => {
    await assert.rejects(
      gateway(
        makeFetch(
          { projects: [{ name: "sandbox" }], services: [] },
          new Response("", { status: 404 }),
        ),
      ).inspectService("sandbox", "missing", "app"),
      expectCode("INVENTORY_INCONSISTENT"),
    );
  });

  await t.test("inspection project omitted by inventory", async () => {
    await assert.rejects(
      gateway(
        makeFetch(
          { projects: [], services: [] },
          new Response(
            JSON.stringify({
              json: { project: { name: "sandbox" }, services: [] },
            }),
          ),
        ),
      ).inspectService("sandbox", "missing", "app"),
      expectCode("INVENTORY_INCONSISTENT"),
    );
  });
});

test("GatewayError has a fixed public shape without an upstream cause or body", () => {
  const error = new GatewayError("UPSTREAM_REJECTED", "Easypanel rejected the operation", 400);

  assert.deepEqual(
    { name: error.name, message: error.message, code: error.code, status: error.status },
    {
      name: "GatewayError",
      message: "Easypanel rejected the operation",
      code: "UPSTREAM_REJECTED",
      status: 400,
    },
  );
  assert.equal("cause" in error, false);
  assert.equal(JSON.stringify(error).includes(PANEL_TOKEN), false);
});

function procedurePaths(): Record<string, unknown> {
  return Object.fromEntries(
    Object.values(PROCEDURES).map((definition) => {
      const candidate = definition.candidates[0] as string;
      return [
        `/api/rpc/${candidate.split(".").join("/")}`,
        { [definition.type === "query" ? "get" : "post"]: {} },
      ];
    }),
  );
}

function rpcMutationFetch(pathname: string, acknowledgement: unknown): typeof globalThis.fetch {
  return async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/api/openapi.json") {
      return new Response(JSON.stringify({ paths: procedurePaths() }));
    }
    if (path === "/api/rpc/update/getStatus") {
      return new Response(JSON.stringify({ json: { version: "2.31.0" } }));
    }
    if (path === pathname) {
      return new Response(JSON.stringify({ json: acknowledgement }));
    }
    throw new Error("unexpected fake request");
  };
}
