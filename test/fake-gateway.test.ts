import assert from "node:assert/strict";
import test from "node:test";

import { SecretRegistry } from "../src/core/redaction.js";
import {
  FakeEasypanelGateway,
  type FakeFixture,
} from "../src/gateway/fake-gateway.js";

const context = { auditId: "audit-offline-1" };

function expectCode(code: string) {
  return (error: unknown): boolean =>
    Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}

test("FakeGateway exposes a complete offline inventory and returns defensive snapshots", async () => {
  const gateway = new FakeEasypanelGateway({
    version: "2.31.0-fake",
    projects: [
      {
        name: "sandbox",
        services: [
          { name: "cache", kind: "redis" },
          { name: "api", kind: "app", envDocument: "KEEP=original" },
          { name: "database", kind: "postgres" },
        ],
      },
    ],
  });

  const capability = await gateway.discover();
  assert.equal(capability.flavor, "fake");
  assert.equal(capability.version, "2.31.0-fake");
  assert.equal(capability.features.has("create_app"), true);
  assert.equal(capability.features.has("create_postgres"), true);
  assert.equal(capability.features.has("create_redis"), true);

  const inventory = await gateway.listInventory();
  assert.deepEqual(
    inventory.services.map(({ project, name, kind }) => ({ project, name, kind })),
    [
      { project: "sandbox", name: "api", kind: "app" },
      { project: "sandbox", name: "cache", kind: "redis" },
      { project: "sandbox", name: "database", kind: "postgres" },
    ],
  );

  const first = await gateway.inspectService("sandbox", "api", "app");
  first.envDocument = "TAMPERED=yes";
  const second = await gateway.inspectService("sandbox", "api", "app");
  assert.equal(second.envDocument, "KEEP=original");
  await assert.rejects(
    gateway.inspectService("sandbox", "api", "postgres"),
    expectCode("SERVICE_KIND_MISMATCH"),
  );
});

test("FakeGateway mutations stay local, carry audit ids, and are naturally idempotent", async () => {
  const gateway = new FakeEasypanelGateway({ version: "2.31.0-fake", projects: [] });

  await gateway.createProject("sandbox", context);
  await gateway.createProject("sandbox", context);
  await gateway.createService("sandbox", "api", "app", {}, context);
  await gateway.createService("sandbox", "api", "app", {}, context);
  await gateway.addDomain(
    "sandbox",
    "api",
    { host: "api.example.test", port: 3000, https: true },
    context,
  );
  await gateway.addDomain(
    "sandbox",
    "api",
    { host: "api.example.test", port: 3000, https: true },
    context,
  );

  assert.deepEqual(
    gateway.mutations.map(({ type, auditId }) => ({ type, auditId })),
    [
      { type: "create_project", auditId: context.auditId },
      { type: "create_service", auditId: context.auditId },
      { type: "add_domain", auditId: context.auditId },
    ],
  );
  assert.equal((await gateway.inspectService("sandbox", "api")).domains?.length, 1);

  await gateway.destroyService("sandbox", "api", "app", context);
  await gateway.destroyService("sandbox", "api", "app", context);
  assert.equal((await gateway.inspectService("sandbox", "api", "app")).exists, false);
  assert.equal(gateway.mutations.filter((entry) => entry.type === "destroy_service").length, 1);
});

test("FakeGateway deployment metadata omits logs and webhook rotation returns only fingerprints", async () => {
  const registry = new SecretRegistry();
  const gateway = new FakeEasypanelGateway(
    {
      version: "2.31.0-fake",
      projects: [{ name: "sandbox", services: [{ name: "api", kind: "app" }] }],
    },
    registry,
  );

  const before = await gateway.getDeployWebhookFingerprint("sandbox", "api");
  await gateway.rotateDeployWebhook("sandbox", "api", context);
  const after = await gateway.getDeployWebhookFingerprint("sandbox", "api");
  assert.match(before ?? "", /^[a-f0-9]{64}$/);
  assert.match(after ?? "", /^[a-f0-9]{64}$/);
  assert.notEqual(after, before);
  assert.equal(String(after).includes("fixture-only-token"), false);

  const deploymentId = await gateway.deployService("sandbox", "api", context);
  const deployments = await gateway.listDeployments("sandbox", "api");
  assert.equal(deployments.length, 1);
  assert.equal("log" in (deployments[0] ?? {}), false);
  assert.equal("requestId" in (deployments[0] ?? {}), false);
  assert.equal(
    (
      await gateway.getDeploymentForRequest(
        deploymentId,
        "sandbox",
        "api",
        context.auditId,
      )
    )?.id,
    deploymentId,
  );
  await assert.rejects(
    gateway.getDeploymentForRequest(
      deploymentId,
      "sandbox",
      "api",
      "different-audit",
    ),
    expectCode("UPSTREAM_TARGET_MISMATCH"),
  );
});

test("FakeGateway validates large fixtures without retaining every environment value globally", async () => {
  const environment = (prefix: string): string =>
    Array.from(
      { length: 300 },
      (_, index) => `${prefix}_${index}=fixture-secret-${prefix}-${index}`,
    ).join("\n");
  const registry = new SecretRegistry();
  registry.add("permanent-fake-gateway-secret");
  const gateway = new FakeEasypanelGateway(
    {
      version: "2.31.0-fake",
      projects: [
        {
          name: "sandbox",
          services: [
            { name: "api", kind: "app", envDocument: environment("API") },
            { name: "worker", kind: "app", envDocument: environment("WORKER") },
          ],
        },
      ],
    },
    registry,
  );
  registry.sealBase();

  const api = await registry.runScoped(() =>
    gateway.inspectService("sandbox", "api", "app"));
  const worker = await registry.runScoped(() =>
    gateway.inspectService("sandbox", "worker", "app"));
  assert.equal(api.envDocument.includes("fixture-secret-API-299"), true);
  assert.equal(worker.envDocument.includes("fixture-secret-WORKER-299"), true);
  assert.equal(
    registry.redactText("fixture-secret-API-299 fixture-secret-WORKER-299"),
    "fixture-secret-API-299 fixture-secret-WORKER-299",
  );

  const replacement = Array.from(
    { length: 512 },
    (_, index) => `KEY_${index}=replacement-secret-${index.toString().padStart(4, "0")}`,
  ).join("\n");
  await registry.runScoped(async () => {
    await gateway.updateEnvironment("sandbox", "api", replacement, context);
    assert.equal(
      registry.redactText("replacement-secret-0511"),
      "[REDACTED]",
    );
  });
});

test("FakeGateway rejects deploying non-app services", async () => {
  const gateway = new FakeEasypanelGateway({
    version: "2.31.0-fake",
    projects: [{ name: "sandbox", services: [{ name: "database", kind: "postgres" }] }],
  });

  await assert.rejects(
    gateway.deployService("sandbox", "database", context),
    expectCode("UNSUPPORTED_SERVICE_KIND"),
  );
  assert.deepEqual(gateway.mutations, []);
});

test("FakeGateway rejects malformed and ambiguous fixtures instead of coercing them", () => {
  const invalidFixtures: unknown[] = [
    { version: "", projects: [] },
    {
      version: "2.31.0-fake",
      projects: [
        {
          name: "sandbox",
          services: [{ name: "api", kind: "mysql" }],
        },
      ],
    },
    {
      version: "2.31.0-fake",
      projects: [
        { name: "sandbox", services: [] },
        { name: "sandbox", services: [] },
      ],
    },
    {
      version: "2.31.0-fake",
      projects: [
        {
          name: "sandbox",
          services: [
            { name: "api", kind: "app" },
            { name: "api", kind: "app" },
          ],
        },
      ],
    },
  ];

  for (const fixture of invalidFixtures) {
    assert.throws(() => new FakeEasypanelGateway(fixture as FakeFixture));
  }
});
