import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { JsonlAuditLog } from "../src/core/audit.js";
import {
  ExternalApprovalStore,
  PlanCryptography,
  type ApprovalAction,
} from "../src/core/external-approval.js";
import { PlanStore } from "../src/core/plan-store.js";
import {
  PolicyEngine,
  createHttpClientSecurityPolicy,
} from "../src/core/policy.js";
import { SecretRegistry } from "../src/core/redaction.js";
import { EnvDocument } from "../src/domain/env-document.js";
import { EasypanelOperator } from "../src/domain/operator.js";
import type { Resources } from "../src/domain/schemas.js";
import type {
  CapabilitySnapshot,
  DeploymentSummary,
  GatewayMutationContext,
  PublicPlan,
} from "../src/domain/types.js";
import {
  FakeEasypanelGateway,
  type FakeFixture,
} from "../src/gateway/fake-gateway.js";
import {
  EnvSecretProvider,
  type SecretProvider,
} from "../src/secrets/env-secret-provider.js";
import { FileWebhookSecretSink } from "../src/secrets/webhook-secret-sink.js";

const APPROVAL_KEY = "offline-approval-key-with-at-least-32-bytes";
const DATABASE_SECRET =
  "postgresql://demo:database-secret-password@database.internal/easypanel_demo";
const DATABASE_PASSWORD = "database-bootstrap-password-secret";
const WATCHDOG_SECRET = "watchdog-secret-added-after-deadline";
const FIXED_NOW = new Date("2026-07-11T12:00:00.000Z");

interface Harness {
  directory: string;
  auditPath: string;
  registry: SecretRegistry;
  gateway: FakeEasypanelGateway;
  approvals: ExternalApprovalStore;
  operator: EasypanelOperator;
  cleanup(): Promise<void>;
}

interface HarnessOptions {
  gatewayFactory?: (registry: SecretRegistry) => FakeEasypanelGateway;
  secretsFactory?: (registry: SecretRegistry) => SecretProvider;
  applyDeadlineMs?: number;
}

async function harness(
  fixture: FakeFixture,
  options: HarnessOptions = {},
): Promise<Harness> {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-offline-"));
  const registry = new SecretRegistry();
  const gateway = options.gatewayFactory?.(registry) ??
    new FakeEasypanelGateway(fixture, registry);
  const cryptography = new PlanCryptography(APPROVAL_KEY);
  const approvals = new ExternalApprovalStore({
    directory: join(directory, "approvals"),
    key: APPROVAL_KEY,
    ttlMs: 60_000,
    now: () => new Date(FIXED_NOW),
  });
  const auditPath = join(directory, "audit", "audit.jsonl");
  const operator = new EasypanelOperator({
    gateway,
    policy: new PolicyEngine({
      accessMode: "admin",
      allowedProjects: ["sandbox"],
      http: createHttpClientSecurityPolicy("https://offline-fixture.invalid"),
    }),
    plans: new PlanStore({
      ttlMs: 60_000,
      replayTtlMs: 60_000,
      now: () => new Date(FIXED_NOW),
    }),
    approvals,
    cryptography,
    secrets: options.secretsFactory?.(registry) ??
      new EnvSecretProvider({
        env: {
          EASYPANEL_TOKEN: "offline-panel-token-never-used",
          EASYPANEL_APPROVAL_KEY: APPROVAL_KEY,
          EASYPANEL_SECRET_DATABASE_URL: DATABASE_SECRET,
          EASYPANEL_SECRET_DATABASE_PASSWORD: DATABASE_PASSWORD,
        },
        registry,
      }),
    webhookSink: new FileWebhookSecretSink(join(directory, "webhook-secrets")),
    audit: new JsonlAuditLog({
      path: auditPath,
      now: () => new Date(FIXED_NOW),
    }),
    actor: "offline-test",
    now: () => new Date(FIXED_NOW),
    ...(options.applyDeadlineMs !== undefined
      ? { applyDeadlineMs: options.applyDeadlineMs }
      : {}),
  });

  return {
    directory,
    auditPath,
    registry,
    gateway,
    approvals,
    operator,
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

async function approve(
  approvals: ExternalApprovalStore,
  plan: PublicPlan,
  action: ApprovalAction,
  target = plan.target,
  includeConfirmation =
    action === "destroy_service" ||
    action === "rotate_deploy_webhook" ||
    action === "stop_service",
): Promise<void> {
  await approvals.create({
    planHash: plan.planHash,
    purpose: "approval",
    action,
    project: target.project,
    service: target.service,
    approver: "offline-approver",
  });
  if (includeConfirmation) {
    await approvals.create({
      planHash: plan.planHash,
      purpose: "confirmation",
      action,
      project: target.project,
      service: target.service,
      approver: "offline-confirmer",
    });
  }
}

function expectCode(code: string) {
  return (error: unknown): boolean =>
    Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}

function baseFixture(services: FakeFixture["projects"][number]["services"]): FakeFixture {
  return {
    version: "2.31.0-fake",
    projects: [{ name: "sandbox", services }],
  };
}

class DeferredSecretProvider implements SecretProvider {
  allowResolve = false;
  resolveCalls = 0;
  readonly #registry: SecretRegistry;

  constructor(registry: SecretRegistry) {
    this.#registry = registry;
  }

  getPanelToken(): string {
    return "offline-panel-token-never-used";
  }

  getApprovalKey(): string {
    return APPROVAL_KEY;
  }

  resolve(name: string): string {
    this.resolveCalls += 1;
    if (!this.allowResolve) {
      throw codedError("SECRET_RESOLVED_TOO_EARLY", "Secret resolution is not allowed yet");
    }
    assert.equal(name, "DATABASE_URL");
    this.#registry.add(DATABASE_SECRET);
    return DATABASE_SECRET;
  }
}

class UncertainResourcesGateway extends FakeEasypanelGateway {
  dispatches = 0;
  #failNextDispatch = true;

  override async updateResources(
    project: string,
    service: string,
    resources: Resources,
    context: GatewayMutationContext,
  ): Promise<void> {
    this.dispatches += 1;
    if (this.#failNextDispatch) {
      this.#failNextDispatch = false;
      throw codedError(
        "UPSTREAM_UNAVAILABLE",
        "The mutation may have reached the upstream before the connection failed",
      );
    }
    await super.updateResources(project, service, resources, context);
  }
}

class DelayedResourcesGateway extends FakeEasypanelGateway {
  readonly #registry: SecretRegistry;
  secretWasScoped = false;

  constructor(fixture: FakeFixture, registry: SecretRegistry) {
    super(fixture, registry);
    this.#registry = registry;
  }

  override async updateResources(
    project: string,
    service: string,
    resources: Resources,
    context: GatewayMutationContext,
  ): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 400));
    this.#registry.add(WATCHDOG_SECRET);
    this.secretWasScoped = this.#registry.redactText(WATCHDOG_SECRET) === "[REDACTED]";
    await super.updateResources(project, service, resources, context);
  }
}

class DelayedApplyPreconditionGateway extends FakeEasypanelGateway {
  #refreshes = 0;

  override async refreshCapabilities(): Promise<CapabilitySnapshot> {
    this.#refreshes += 1;
    if (this.#refreshes >= 2) {
      await new Promise<void>((resolve) => setTimeout(resolve, 400));
    }
    return super.refreshCapabilities();
  }
}

class DriftingCapabilitiesGateway extends FakeEasypanelGateway {
  refreshes = 0;

  override async refreshCapabilities(): Promise<CapabilitySnapshot> {
    const capability = await super.refreshCapabilities();
    this.refreshes += 1;
    if (this.refreshes < 2) return capability;
    return {
      ...capability,
      features: new Set(
        [...capability.features].filter((feature) => feature !== "update_resources"),
      ),
      procedures: new Map(
        [...capability.procedures].filter(
          ([procedure]) => procedure !== "services.app.updateResources",
        ),
      ),
    };
  }
}

class StaleLifecycleActionGateway extends FakeEasypanelGateway {
  #staleActionId?: string;

  async seedCompletedRestart(project: string, service: string): Promise<string> {
    this.#staleActionId = await super.restartService(project, service, {
      auditId: "seed-completed-restart",
    });
    return this.#staleActionId;
  }

  override async restartService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    if (this.#staleActionId) return this.#staleActionId;
    return super.restartService(project, service, context);
  }
}

class StaleDeploymentGateway extends FakeEasypanelGateway {
  #staleDeploymentId?: string;

  async seedCompletedDeploy(project: string, service: string): Promise<string> {
    this.#staleDeploymentId = await super.deployService(project, service, {
      auditId: "seed-completed-deploy",
    });
    return this.#staleDeploymentId;
  }

  override async listDeployments(
    project: string,
    service: string,
  ): Promise<DeploymentSummary[]> {
    const deployments = await super.listDeployments(project, service);
    return deployments.filter(({ id }) => id !== this.#staleDeploymentId);
  }

  override async deployService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    if (this.#staleDeploymentId) return this.#staleDeploymentId;
    return super.deployService(project, service, context);
  }
}

function codedError(code: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, "code", { value: code });
  return error;
}

test("offline planner/apply converges app, Postgres, and Redis with secret refs and replay", async () => {
  const h = await harness(
    baseFixture([
      {
        name: "api",
        kind: "app",
        envDocument: "# preserve this comment\nKEEP=untouched\nDATABASE_URL=old-value",
      },
    ]),
  );

  try {
    const appPlan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      ensure: "present",
      source: { type: "image", image: "ghcr.io/example/api:2026-07-11" },
      environment: {
        merge: {
          DATABASE_URL: { from: "secret", name: "DATABASE_URL" },
          PUBLIC_MODE: { from: "literal", value: "production" },
        },
        remove: [],
      },
      resources: {
        memoryReservationMb: 256,
        memoryLimitMb: 512,
        cpuReservation: 0.25,
        cpuLimit: 1,
      },
      deploy: { replicas: 2, zeroDowntime: true },
      domains: [{ host: "api.example.test", port: 3000, https: true }],
      healthcheck: {
        path: "/health",
        port: 3000,
        intervalSeconds: 30,
        timeoutSeconds: 5,
      },
    });

    assert.equal(JSON.stringify(appPlan).includes(DATABASE_SECRET), false);
    assert.equal("preconditionHash" in appPlan, false);
    assert.equal("capabilityHash" in appPlan, false);
    assert.equal("secretFingerprints" in appPlan, false);
    assert.deepEqual(
      appPlan.actions.map((action) => action.type),
      [
        "update_source",
        "merge_environment",
        "update_resources",
        "update_deploy",
        "add_domain",
        "update_healthcheck",
      ],
    );

    await approve(h.approvals, appPlan, "apply_service");
    const appResult = await h.operator.applyPlan(appPlan.planHash, appPlan.target);
    assert.equal(appResult.changed, true);
    assert.equal(appResult.verified, true);
    assert.equal(appResult.idempotentReplay, false);

    const internalApp = await h.gateway.inspectService("sandbox", "api", "app");
    const environment = EnvDocument.parse(internalApp.envDocument);
    assert.equal(environment.get("KEEP"), "untouched");
    assert.equal(environment.get("DATABASE_URL"), DATABASE_SECRET);
    assert.equal(environment.get("PUBLIC_MODE"), "production");
    assert.equal(internalApp.source?.type, "image");
    assert.equal(internalApp.domains?.[0]?.host, "api.example.test");

    const publicApp = await h.operator.inspectService("sandbox", "api");
    assert.deepEqual(publicApp.environmentNames, ["DATABASE_URL", "KEEP", "PUBLIC_MODE"]);
    assert.equal("envDocument" in publicApp, false);
    assert.equal(JSON.stringify(publicApp).includes(DATABASE_SECRET), false);

    for (const [service, kind] of [
      ["database", "postgres"],
      ["cache", "redis"],
    ] as const) {
      const plan = await h.operator.planService({
        project: "sandbox",
        service,
        kind,
        ensure: "present",
        database: {
          initialPassword: { from: "secret", name: "DATABASE_PASSWORD" },
        },
      });
      assert.deepEqual(plan.actions.map((action) => action.type), ["create_service"]);
      assert.equal(JSON.stringify(plan).includes(DATABASE_PASSWORD), false);
      await approve(h.approvals, plan, "apply_service");
      const result = await h.operator.applyPlan(plan.planHash, plan.target);
      assert.equal(result.verified, true);
      assert.equal((await h.gateway.inspectService("sandbox", service, kind)).kind, kind);
    }

    const mutationCount = h.gateway.mutations.length;
    const replay = await h.operator.applyPlan(appPlan.planHash, appPlan.target);
    assert.equal(replay.idempotentReplay, true);
    assert.equal(replay.changed, false);
    assert.deepEqual(replay.appliedActions, []);
    assert.equal(h.gateway.mutations.length, mutationCount);

    const audit = await readFile(h.auditPath, "utf8");
    assert.equal(audit.includes(DATABASE_SECRET), false);
    assert.equal(audit.includes("database-secret-password"), false);
    assert.equal(audit.includes(DATABASE_PASSWORD), false);
    assert.equal(audit.includes("envDocument"), false);
    assert.equal(audit.split("\n").filter(Boolean).every((line) => JSON.parse(line)), true);
    const auditEvents = audit
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(
      auditEvents.some(
        (event) =>
          event.action === "apply_update_source" &&
          Array.isArray(event.appliedActions) &&
          event.appliedActions.includes("update_source"),
      ),
      true,
    );
  } finally {
    await h.cleanup();
  }
});

test("secret references remain unresolved until apply has consumed external approval", async () => {
  let deferred: DeferredSecretProvider | undefined;
  const h = await harness(
    baseFixture([
      { name: "api", kind: "app", envDocument: "DATABASE_URL=old-database-url-value" },
    ]),
    {
      secretsFactory: (registry) => {
        deferred = new DeferredSecretProvider(registry);
        return deferred;
      },
    },
  );
  assert.ok(deferred);
  const secrets = deferred;

  try {
    const plan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      ensure: "present",
      environment: {
        merge: {
          DATABASE_URL: { from: "secret", name: "DATABASE_URL" },
        },
        remove: [],
      },
    });
    assert.equal(secrets.resolveCalls, 0);
    assert.equal(JSON.stringify(plan).includes(DATABASE_SECRET), false);

    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("APPROVAL_REQUIRED"),
    );
    assert.equal(secrets.resolveCalls, 0);

    await approve(h.approvals, plan, "apply_service");
    secrets.allowResolve = true;
    const result = await h.operator.applyPlan(plan.planHash, plan.target);
    assert.equal(result.verified, true);
    assert.equal(secrets.resolveCalls > 0, true);
    assert.equal(
      EnvDocument.parse(
        (await h.gateway.inspectService("sandbox", "api", "app")).envDocument,
      ).get("DATABASE_URL"),
      DATABASE_SECRET,
    );
  } finally {
    await h.cleanup();
  }
});

test("database bootstrap credentials are mandatory for creation and rejected for existing services", async () => {
  const h = await harness(
    baseFixture([{ name: "existing-db", kind: "postgres" }]),
  );
  try {
    await assert.rejects(
      h.operator.planService({
        project: "sandbox",
        service: "new-db",
        kind: "postgres",
        ensure: "present",
      }),
      expectCode("DATABASE_BOOTSTRAP_REQUIRED"),
    );
    await assert.rejects(
      h.operator.planService({
        project: "sandbox",
        service: "existing-db",
        kind: "postgres",
        ensure: "present",
        database: {
          initialPassword: { from: "secret", name: "DATABASE_PASSWORD" },
        },
      }),
      expectCode("DATABASE_BOOTSTRAP_CREATION_ONLY"),
    );
  } finally {
    await h.cleanup();
  }
});

test("an uncertain post-dispatch failure poisons the plan and requires a fresh plan", async () => {
  let uncertain: UncertainResourcesGateway | undefined;
  const fixture = baseFixture([{ name: "api", kind: "app", envDocument: "KEEP=one" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => {
      uncertain = new UncertainResourcesGateway(fixture, registry);
      return uncertain;
    },
  });
  assert.ok(uncertain);
  const gateway = uncertain;
  const spec = {
    project: "sandbox",
    service: "api",
    kind: "app",
    ensure: "present",
    resources: {
      memoryReservationMb: 128,
      memoryLimitMb: 256,
      cpuReservation: 0.1,
      cpuLimit: 0.5,
    },
  } as const;

  try {
    const plan = await h.operator.planService(spec);
    await approve(h.approvals, plan, "apply_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("UPSTREAM_UNAVAILABLE"),
    );
    assert.equal(gateway.dispatches, 1);

    await approve(h.approvals, plan, "apply_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("PLAN_UNCERTAIN"),
    );
    assert.equal(gateway.dispatches, 1);

    await assert.rejects(
      h.operator.planService(spec),
      expectCode("PLAN_UNCERTAIN"),
    );

    await gateway.updateEnvironment(
      "sandbox",
      "api",
      "KEEP=state-inspected-after-uncertain-mutation",
      { auditId: "post-failure-inspection" },
    );
    const replanned = await h.operator.planService(spec);
    assert.notEqual(replanned.planHash, plan.planHash);
    await approve(h.approvals, replanned, "apply_service");
    const result = await h.operator.applyPlan(replanned.planHash, replanned.target);
    assert.equal(result.verified, true);
    assert.equal(gateway.dispatches, 2);
  } finally {
    await h.cleanup();
  }
});

test("an apply watchdog waits for dispatched work to settle and then halts mutations", async () => {
  const fixture = baseFixture([{ name: "api", kind: "app" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => new DelayedResourcesGateway(fixture, registry),
    applyDeadlineMs: 200,
  });

  try {
    const plan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      resources: {
        memoryReservationMb: 128,
        memoryLimitMb: 256,
        cpuReservation: 0.1,
        cpuLimit: 0.5,
      },
    });
    await approve(h.approvals, plan, "apply_service");
    h.registry.sealBase();
    await assert.rejects(
      h.registry.runScoped(() => h.operator.applyPlan(plan.planHash, plan.target)),
      expectCode("PLAN_UNCERTAIN"),
    );
    assert.equal((h.gateway as DelayedResourcesGateway).secretWasScoped, true);
    assert.equal(h.registry.redactText(WATCHDOG_SECRET), WATCHDOG_SECRET);
    assert.deepEqual(
      (await h.registry.runScoped(() =>
        h.gateway.inspectService("sandbox", "api", "app"))).resources,
      {
        memoryReservationMb: 128,
        memoryLimitMb: 256,
        cpuReservation: 0.1,
        cpuLimit: 0.5,
      },
    );
    await assert.rejects(
      h.registry.runScoped(() => h.operator.applyPlan(plan.planHash, plan.target)),
      expectCode("PLAN_UNCERTAIN"),
    );
  } finally {
    await h.cleanup();
  }
});

test("an apply watchdog checkpoint prevents a late first mutation after precondition delay", async () => {
  const fixture = baseFixture([{ name: "api", kind: "app" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => new DelayedApplyPreconditionGateway(fixture, registry),
    applyDeadlineMs: 200,
  });

  try {
    const plan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      resources: {
        memoryReservationMb: 128,
        memoryLimitMb: 256,
        cpuReservation: 0.1,
        cpuLimit: 0.5,
      },
    });
    await approve(h.approvals, plan, "apply_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("PLAN_UNCERTAIN"),
    );
    assert.equal(h.gateway.mutations.length, 0);
    assert.equal(
      (await h.gateway.inspectService("sandbox", "api", "app")).resources,
      undefined,
    );
  } finally {
    await h.cleanup();
  }
});

test("offline apply fails closed when the service precondition becomes stale", async () => {
  const h = await harness(
    baseFixture([{ name: "api", kind: "app", envDocument: "KEEP=original" }]),
  );

  try {
    const plan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      ensure: "present",
      resources: {
        memoryReservationMb: 128,
        memoryLimitMb: 256,
        cpuReservation: 0.1,
        cpuLimit: 0.5,
      },
    });
    await approve(h.approvals, plan, "apply_service");

    await h.gateway.updateEnvironment(
      "sandbox",
      "api",
      "KEEP=changed-by-another-actor",
      { auditId: "concurrent-change" },
    );

    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("PRECONDITION_CHANGED"),
    );
    const snapshot = await h.gateway.inspectService("sandbox", "api", "app");
    assert.equal(snapshot.resources, undefined);
    assert.equal(
      h.gateway.mutations.some((entry) => entry.type === "update_resources"),
      false,
    );

    const events = (await readFile(h.auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(
      events.some(
        (event) => event.outcome === "failed" && event.errorCode === "PRECONDITION_CHANGED",
      ),
      true,
    );
  } finally {
    await h.cleanup();
  }
});

test("apply fails before its first mutation when the capability profile changed", async () => {
  let drifting: DriftingCapabilitiesGateway | undefined;
  const fixture = baseFixture([{ name: "api", kind: "app" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => {
      drifting = new DriftingCapabilitiesGateway(fixture, registry);
      return drifting;
    },
  });
  assert.ok(drifting);
  try {
    const plan = await h.operator.planService({
      project: "sandbox",
      service: "api",
      kind: "app",
      resources: {
        memoryReservationMb: 128,
        memoryLimitMb: 256,
        cpuReservation: 0.1,
        cpuLimit: 0.5,
      },
    });
    await approve(h.approvals, plan, "apply_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("PRECONDITION_CHANGED"),
    );
    assert.equal(
      drifting.mutations.some((mutation) => mutation.type === "update_resources"),
      false,
    );
  } finally {
    await h.cleanup();
  }
});

test("typed lifecycle plans enforce critical stop confirmation and strict readiness", async () => {
  const h = await harness(baseFixture([{ name: "api", kind: "app", status: "running" }]));

  try {
    const stop = await h.operator.planOperation("stop", "sandbox", "api");
    assert.equal(stop.confirmation?.includes("--purpose confirmation"), true);
    await h.approvals.create({
      planHash: stop.planHash,
      purpose: "approval",
      action: "stop_service",
      approver: "offline-approver",
      ...stop.target,
    });
    await assert.rejects(
      h.operator.applyPlan(stop.planHash, {
        ...stop.target,
        action: "stop_service",
      }),
      expectCode("CONFIRMATION_REQUIRED"),
    );

    await approve(h.approvals, stop, "stop_service");
    const stopped = await h.operator.applyPlan(stop.planHash, {
      ...stop.target,
      action: "stop_service",
    });
    assert.equal(stopped.verified, true);
    assert.match(stopped.actionId ?? "", /^fake-lifecycle-/);
    assert.equal((await h.operator.checkServiceHealth("sandbox", "api")).readiness, "not_ready");

    const alreadyStopped = await h.operator.planOperation("stop", "sandbox", "api");
    assert.equal(alreadyStopped.noChanges, true);
    const noChange = await h.operator.applyPlan(alreadyStopped.planHash, {
      ...alreadyStopped.target,
      action: "stop_service",
    });
    assert.equal(noChange.changed, false);

    const start = await h.operator.planOperation("start", "sandbox", "api");
    await approve(h.approvals, start, "start_service");
    await h.operator.applyPlan(start.planHash, {
      ...start.target,
      action: "start_service",
    });
    assert.equal((await h.operator.checkServiceHealth("sandbox", "api")).readiness, "ready");

    const restart = await h.operator.planOperation("restart", "sandbox", "api");
    await approve(h.approvals, restart, "restart_service");
    const restarted = await h.operator.applyPlan(restart.planHash, {
      ...restart.target,
      action: "restart_service",
    });
    assert.match(restarted.actionId ?? "", /^fake-lifecycle-/);
    const replayedRestart = await h.operator.applyPlan(restart.planHash, {
      ...restart.target,
      action: "restart_service",
    });
    assert.equal(replayedRestart.idempotentReplay, true);

    const secondRestart = await h.operator.planOperation("restart", "sandbox", "api");
    assert.notEqual(secondRestart.planHash, restart.planHash);
    await approve(h.approvals, secondRestart, "restart_service");
    const restartedAgain = await h.operator.applyPlan(secondRestart.planHash, {
      ...secondRestart.target,
      action: "restart_service",
    });
    assert.notEqual(restartedAgain.actionId, restarted.actionId);
    const lifecycleAudit = await readFile(h.auditPath, "utf8");
    assert.equal(lifecycleAudit.includes(restarted.actionId ?? "missing"), true);
    assert.deepEqual(
      h.gateway.mutations
        .filter((entry) => entry.type.endsWith("_service"))
        .map((entry) => entry.type),
      ["stop_service", "start_service", "restart_service", "restart_service"],
    );
  } finally {
    await h.cleanup();
  }
});

test("lifecycle verification rejects an action id that existed before the plan", async () => {
  let stale: StaleLifecycleActionGateway | undefined;
  const fixture = baseFixture([{ name: "api", kind: "app", status: "running" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => {
      stale = new StaleLifecycleActionGateway(fixture, registry);
      return stale;
    },
  });
  assert.ok(stale);
  try {
    const oldActionId = await stale.seedCompletedRestart("sandbox", "api");
    const plan = await h.operator.planOperation("restart", "sandbox", "api");
    await approve(h.approvals, plan, "restart_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        ...plan.target,
        action: "restart_service",
      }),
      expectCode("VERIFY_FAILED"),
    );
    assert.equal(
      plan.actions.length > 0 &&
        (await stale.listLifecycleActions("sandbox", "api")).some(
          (action) => action.id === oldActionId,
        ),
      true,
    );
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, plan.target),
      expectCode("PLAN_UNCERTAIN"),
    );
  } finally {
    await h.cleanup();
  }
});

test("deploy verification rejects a stale id omitted from the bounded pre-plan window", async () => {
  let stale: StaleDeploymentGateway | undefined;
  const fixture = baseFixture([{ name: "api", kind: "app", status: "running" }]);
  const h = await harness(fixture, {
    gatewayFactory: (registry) => {
      stale = new StaleDeploymentGateway(fixture, registry);
      return stale;
    },
  });
  assert.ok(stale);

  try {
    const staleId = await stale.seedCompletedDeploy("sandbox", "api");
    const plan = await h.operator.planOperation("deploy", "sandbox", "api");
    await approve(h.approvals, plan, "deploy_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        ...plan.target,
        action: "deploy_service",
      }),
      expectCode("UPSTREAM_TARGET_MISMATCH"),
    );
    assert.equal(staleId.startsWith("fake-action-"), true);
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        ...plan.target,
        action: "deploy_service",
      }),
      expectCode("PLAN_UNCERTAIN"),
    );
  } finally {
    await h.cleanup();
  }
});

test("a completed desired-state cycle receives a fresh plan generation", async () => {
  const resourcesA: Resources = {
    memoryReservationMb: 128,
    memoryLimitMb: 256,
    cpuReservation: 0.1,
    cpuLimit: 0.5,
  };
  const resourcesB: Resources = {
    memoryReservationMb: 256,
    memoryLimitMb: 512,
    cpuReservation: 0.25,
    cpuLimit: 1,
  };
  const h = await harness(baseFixture([{ name: "api", kind: "app", resources: resourcesA }]));
  const spec = (resources: Resources) => ({
    project: "sandbox",
    service: "api",
    kind: "app" as const,
    ensure: "present" as const,
    resources,
  });

  try {
    const firstB = await h.operator.planService(spec(resourcesB));
    const duplicateB = await h.operator.planService(spec(resourcesB));
    assert.equal(duplicateB.planHash, firstB.planHash);
    await approve(h.approvals, firstB, "apply_service");
    await h.operator.applyPlan(firstB.planHash, firstB.target);

    const backToA = await h.operator.planService(spec(resourcesA));
    await approve(h.approvals, backToA, "apply_service");
    await h.operator.applyPlan(backToA.planHash, backToA.target);

    const secondB = await h.operator.planService(spec(resourcesB));
    assert.notEqual(secondB.planHash, firstB.planHash);
    await approve(h.approvals, secondB, "apply_service");
    const appliedSecondB = await h.operator.applyPlan(secondB.planHash, secondB.target);
    assert.equal(appliedSecondB.changed, true);
    assert.equal(
      h.gateway.mutations.filter((entry) => entry.type === "update_resources").length,
      3,
    );
  } finally {
    await h.cleanup();
  }
});

test("offline deploy is idempotent and deployment-log content stays disabled", async () => {
  const fixture = baseFixture([{ name: "api", kind: "app" }]);
  const h = await harness(fixture);

  try {
    const plan = await h.operator.planOperation("deploy", "sandbox", "api");
    await approve(h.approvals, plan, "deploy_service");
    const first = await h.operator.applyPlan(plan.planHash, {
      project: "sandbox",
      service: "api",
      action: "deploy_service",
    });
    assert.equal(first.verified, true);

    const mutationCount = h.gateway.mutations.length;
    const replay = await h.operator.applyPlan(plan.planHash, {
      project: "sandbox",
      service: "api",
      action: "deploy_service",
    });
    assert.equal(replay.idempotentReplay, true);
    assert.equal(h.gateway.mutations.length, mutationCount);

    const logs = await h.operator.getSanitizedLogs("sandbox", "api", 50);
    assert.deepEqual({ trust: logs.trust, source: logs.source }, {
      trust: "untrusted",
      source: "policy",
    });
    assert.equal(
      logs.content,
      "[UNTRUSTED_LOG] Deployment log content is disabled by security policy",
    );
  } finally {
    await h.cleanup();
  }
});

test("destroy approval and apply are bound to the exact planned target", async () => {
  const h = await harness(
    baseFixture([
      { name: "api", kind: "app" },
      { name: "worker", kind: "app" },
    ]),
  );

  try {
    const plan = await h.operator.planDestroy("sandbox", "api");
    assert.deepEqual(plan.actions.map((action) => action.type), ["destroy_service"]);

    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        project: "sandbox",
        service: "api",
        action: "destroy_service",
      }),
      expectCode("APPROVAL_REQUIRED"),
    );
    assert.equal((await h.gateway.inspectService("sandbox", "api")).exists, true);

    await approve(h.approvals, plan, "destroy_service", {
      project: "sandbox",
      service: "worker",
    }, false);
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        project: "sandbox",
        service: "api",
        action: "destroy_service",
      }),
      expectCode("APPROVAL_INVALID"),
    );
    assert.equal((await h.gateway.inspectService("sandbox", "api")).exists, true);
    assert.equal((await h.gateway.inspectService("sandbox", "worker")).exists, true);

    await approve(h.approvals, plan, "destroy_service");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        project: "sandbox",
        service: "worker",
        action: "destroy_service",
      }),
      expectCode("PLAN_TARGET_MISMATCH"),
    );

    const result = await h.operator.applyPlan(plan.planHash, {
      project: "sandbox",
      service: "api",
      action: "destroy_service",
    });
    assert.equal(result.verified, true);
    assert.equal((await h.gateway.inspectService("sandbox", "api", "app")).exists, false);
    assert.equal((await h.gateway.inspectService("sandbox", "worker", "app")).exists, true);
    assert.deepEqual(
      h.gateway.mutations
        .filter((entry) => entry.type === "destroy_service")
        .map(({ project, service }) => ({ project, service })),
      [{ project: "sandbox", service: "api" }],
    );
  } finally {
    await h.cleanup();
  }
});

test("deploy-webhook rotation is target-bound, verified by fingerprint, and never returns a token", async () => {
  const h = await harness(
    baseFixture([
      { name: "api", kind: "app" },
      { name: "worker", kind: "app" },
    ]),
  );

  try {
    const apiBefore = await h.gateway.getDeployWebhookFingerprint("sandbox", "api");
    const workerBefore = await h.gateway.getDeployWebhookFingerprint("sandbox", "worker");
    const plan = await h.operator.planOperation(
      "rotate_deploy_webhook",
      "sandbox",
      "api",
    );
    assert.deepEqual(plan.actions.map((action) => action.type), ["rotate_deploy_webhook"]);

    await approve(h.approvals, plan, "rotate_deploy_webhook");
    await assert.rejects(
      h.operator.applyPlan(plan.planHash, {
        project: "sandbox",
        service: "worker",
        action: "rotate_deploy_webhook",
      }),
      expectCode("PLAN_TARGET_MISMATCH"),
    );

    const result = await h.operator.applyPlan(plan.planHash, {
      project: "sandbox",
      service: "api",
      action: "rotate_deploy_webhook",
    });
    const apiAfter = await h.gateway.getDeployWebhookFingerprint("sandbox", "api");
    const workerAfter = await h.gateway.getDeployWebhookFingerprint("sandbox", "worker");
    assert.notEqual(apiAfter, apiBefore);
    assert.equal(workerAfter, workerBefore);
    assert.equal(result.verified, true);
    const sinkPath = join(h.directory, "webhook-secrets", "sandbox--api.deploy-webhook");
    const [sinkContents, sinkMetadata] = await Promise.all([
      readFile(sinkPath, "utf8"),
      stat(sinkPath),
    ]);
    assert.equal(sinkContents.startsWith("fixture-only-token-"), true);
    assert.equal(sinkMetadata.mode & 0o777, 0o600);
    assert.equal(JSON.stringify(result).includes("fixture-only-token"), false);
    assert.deepEqual(
      h.gateway.mutations
        .filter((entry) => entry.type === "rotate_deploy_webhook")
        .map(({ project, service }) => ({ project, service })),
      [{ project: "sandbox", service: "api" }],
    );

    const audit = await readFile(h.auditPath, "utf8");
    assert.equal(audit.includes("fixture-only-token"), false);
    assert.equal(audit.includes("webhookFingerprint"), false);
  } finally {
    await h.cleanup();
  }
});

test("query policy denials are audited before any gateway read", async () => {
  const h = await harness(baseFixture([{ name: "api", kind: "app" }]));
  try {
    await assert.rejects(
      h.operator.inspectService("forbidden", "api"),
      expectCode("PROJECT_DENIED"),
    );
    const events = (await readFile(h.auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0], {
      schemaVersion: 1,
      auditId: events[0]?.auditId,
      timestamp: FIXED_NOW.toISOString(),
      actor: "offline-test",
      action: "inspect_service",
      outcome: "denied",
      target: { project: "forbidden", service: "api" },
      errorCode: "PROJECT_DENIED",
      changed: false,
    });
  } finally {
    await h.cleanup();
  }
});
