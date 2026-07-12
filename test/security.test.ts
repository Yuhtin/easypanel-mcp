import assert from "node:assert/strict";
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ConfigError, loadConfig } from "../src/config.js";
import {
  JsonlAuditLog,
  type AuditEventInput,
} from "../src/core/audit.js";
import {
  ExternalApprovalError,
  ExternalApprovalStore,
  PlanCryptography,
  approvalActionForPlan,
} from "../src/core/external-approval.js";
import {
  PlanStore,
  PlanStoreError,
  type NewStoredPlan,
  type PlanStoreErrorCode,
} from "../src/core/plan-store.js";
import {
  PolicyEngine,
  PolicyError,
  createHttpClientSecurityPolicy,
} from "../src/core/policy.js";
import { SecretRegistry } from "../src/core/redaction.js";
import { isCriticalPlan } from "../src/core/risk.js";
import { SingleInstanceLock } from "../src/core/single-instance.js";
import { ServiceSpecSchema } from "../src/domain/schemas.js";
import type { ApplyResult, PlanActionType, Risk } from "../src/domain/types.js";
import {
  EnvSecretProvider,
  SecretProviderError,
} from "../src/secrets/env-secret-provider.js";
import { FileWebhookSecretSink } from "../src/secrets/webhook-secret-sink.js";

const PANEL_TOKEN = "panel-token-that-must-never-be-serialized";

function configEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    EASYPANEL_URL: "https://panel.example.com",
    EASYPANEL_TOKEN: PANEL_TOKEN,
    EASYPANEL_ALLOWED_PROJECTS: "sandbox",
    EASYPANEL_EXPECTED_VERSION: "2.31.0",
    ...overrides,
  };
}

function expectPlanError(code: PlanStoreErrorCode) {
  return (error: unknown): boolean =>
    error instanceof PlanStoreError && error.code === code;
}

function expectApprovalError(code: ExternalApprovalError["code"]) {
  return (error: unknown): boolean =>
    error instanceof ExternalApprovalError && error.code === code;
}

function newPlan(options: {
  planHash?: string;
  intentHash?: string;
  action?: PlanActionType;
  risk?: Risk;
  project?: string;
  service?: string;
} = {}): NewStoredPlan {
  const action = options.action ?? "deploy_service";
  return {
    planHash: options.planHash ?? "a".repeat(64),
    intentHash: options.intentHash ?? "9".repeat(64),
    target: {
      project: options.project ?? "sandbox",
      service: options.service ?? "api",
    },
    actions: [
      {
        id: `${action}-1`,
        type: action,
        risk: options.risk ?? "medium",
        summary: `Apply ${action}`,
        changedFields: ["deployment"],
      },
    ],
    noChanges: false,
    operation:
      action === "rotate_deploy_webhook"
        ? "rotate_deploy_webhook"
        : action === "deploy_service"
          ? "deploy"
          : undefined,
    preconditionHash: "b".repeat(64),
    capabilityHash: "c".repeat(64),
    approval: "An external approval file is required",
  };
}

test("critical classification cannot be downgraded by lowering stop/destroy/rotate risk", () => {
  for (const action of [
    "stop_service",
    "destroy_service",
    "rotate_deploy_webhook",
  ] as const) {
    assert.equal(isCriticalPlan(newPlan({ action, risk: "low" })), true);
  }
});

test("plan generations are unique while their deterministic intent remains stable", () => {
  const cryptography = new PlanCryptography("plan-generation-key-material".repeat(2));
  const intent = cryptography.signPlan({ purpose: "test-intent", target: "sandbox/api" });
  const first = cryptography.createPlanHash(intent);
  const second = cryptography.createPlanHash(intent);
  assert.match(intent, /^[a-f0-9]{64}$/);
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.match(second, /^[a-f0-9]{64}$/);
  assert.notEqual(first, second);
});

test("configuration requires a bare HTTPS origin and secure TLS", () => {
  for (const invalidOrigin of [
    "http://panel.example.com",
    "https://user:password@panel.example.com",
    "https://panel.example.com/api",
    "https://panel.example.com/?token=secret",
  ]) {
    assert.throws(
      () => loadConfig(configEnv({ EASYPANEL_URL: invalidOrigin })),
      ConfigError,
    );
  }

  assert.throws(
    () => loadConfig(configEnv({ NODE_TLS_REJECT_UNAUTHORIZED: "0" })),
    ConfigError,
  );
  assert.throws(
    () => loadConfig(configEnv({ EASYPANEL_TLS_REJECT_UNAUTHORIZED: "0" })),
    ConfigError,
  );
});

test("configuration defaults to readonly and requires an explicit project allowlist", () => {
  const config = loadConfig(configEnv());

  assert.equal(config.accessMode, "readonly");
  assert.deepEqual([...config.allowedProjects], ["sandbox"]);
  assert.equal(config.http.requireHttps, true);
  assert.equal(config.http.redirect, "error");
  assert.equal(config.http.rejectUnauthorized, true);
  assert.equal(config.tokenEnvName, "EASYPANEL_TOKEN");
  assert.equal("token" in config, false);
  assert.equal(JSON.stringify(config).includes(PANEL_TOKEN), false);

  const withoutVersion = configEnv();
  delete withoutVersion.EASYPANEL_EXPECTED_VERSION;
  assert.throws(() => loadConfig(withoutVersion), ConfigError);
  assert.throws(
    () => loadConfig(configEnv({ EASYPANEL_SECRET_PREFIX: "EASYPANEL_" })),
    ConfigError,
  );

  for (const projects of [undefined, "", "*", "sandbox,*", "Sandbox"] as const) {
    const env = configEnv();
    if (projects === undefined) {
      delete env.EASYPANEL_ALLOWED_PROJECTS;
    } else {
      env.EASYPANEL_ALLOWED_PROJECTS = projects;
    }
    assert.throws(() => loadConfig(env), ConfigError);
  }
});

test("configuration rejects every local state path collision", () => {
  for (const overrides of [
    {
      EASYPANEL_AUDIT_PATH: "/tmp/easypanel-state/shared",
      EASYPANEL_RUNTIME_LOCK_PATH: "/tmp/easypanel-state/shared",
    },
    {
      EASYPANEL_AUDIT_PATH: "/tmp/easypanel-state/approvals/audit.jsonl",
      EASYPANEL_APPROVAL_DIR: "/tmp/easypanel-state/approvals",
    },
    {
      EASYPANEL_RUNTIME_LOCK_PATH: "/tmp/easypanel-state/webhooks/runtime.lock",
      EASYPANEL_WEBHOOK_SINK_DIR: "/tmp/easypanel-state/webhooks",
    },
    {
      EASYPANEL_AUDIT_PATH: "/tmp/easypanel-state/private",
      EASYPANEL_APPROVAL_DIR: "/tmp/easypanel-state/private/approvals",
    },
    {
      EASYPANEL_APPROVAL_DIR: "/tmp/easypanel-state/private",
      EASYPANEL_WEBHOOK_SINK_DIR: "/tmp/easypanel-state/private/webhooks",
    },
    {
      EASYPANEL_FAKE_FIXTURE: "/tmp/easypanel-state/fixture.json",
      EASYPANEL_AUDIT_PATH: "/tmp/easypanel-state/fixture.json",
    },
    {
      EASYPANEL_FAKE_FIXTURE: "/tmp/easypanel-state/approvals/fixture.json",
      EASYPANEL_APPROVAL_DIR: "/tmp/easypanel-state/approvals",
    },
  ]) {
    assert.throws(() => loadConfig(configEnv(overrides)), ConfigError);
  }
});

test("service schemas reject credential-bearing sources, traversal, free commands, and HTTP domains", () => {
  const base = {
    project: "sandbox",
    service: "api",
    kind: "app",
    ensure: "present",
  } as const;
  for (const invalid of [
    { ...base, source: { type: "image", image: "user:pass@registry.example/repo:tag" } },
    {
      ...base,
      source: { type: "git", repository: "example/api", ref: "main", path: "/../../secret" },
    },
    {
      ...base,
      source: { type: "git", repository: "example/api", ref: "main\u202e", path: "/" },
    },
    { ...base, healthcheck: { path: "/ready\u007f", port: 3000 } },
    { ...base, healthcheck: { path: "/ready?token=do-not-reflect", port: 3000 } },
    { ...base, deploy: { replicas: 1, zeroDowntime: true, command: "cat /run/secrets/x" } },
    { ...base, deploy: { replicas: 21, zeroDowntime: true } },
    {
      ...base,
      resources: {
        memoryReservationMb: 0,
        memoryLimitMb: 0,
        cpuReservation: 0,
        cpuLimit: 0,
      },
    },
    {
      ...base,
      resources: {
        memoryReservationMb: 32_769,
        memoryLimitMb: 32_769,
        cpuReservation: 33,
        cpuLimit: 33,
      },
    },
    { ...base, domains: [{ host: "api.example.test", port: 3000, https: false }] },
  ]) {
    assert.equal(ServiceSpecSchema.safeParse(invalid).success, false);
  }
});

test("policy exposes redirect denial and enforces exact project and mode boundaries", () => {
  const http = createHttpClientSecurityPolicy("https://panel.example.com");
  const readonly = new PolicyEngine({ allowedProjects: ["sandbox"], http });

  assert.equal(readonly.http.redirect, "error");
  assert.deepEqual(readonly.evaluate({ project: "sandbox", operation: "query" }), {
    allowed: true,
    code: "ALLOWED",
  });
  assert.deepEqual(readonly.evaluate({ project: "sandbox-copy", operation: "query" }), {
    allowed: false,
    code: "PROJECT_DENIED",
  });
  assert.deepEqual(
    readonly.evaluate({
      project: "sandbox",
      operation: "mutation",
      action: "deploy_service",
      risk: "medium",
    }),
    { allowed: false, code: "READONLY" },
  );

  const operator = new PolicyEngine({
    accessMode: "operator",
    allowedProjects: ["sandbox"],
    http,
  });
  assert.deepEqual(
    operator.evaluate({
      project: "sandbox",
      operation: "mutation",
      action: "destroy_service",
      risk: "critical",
    }),
    { allowed: false, code: "ADMIN_REQUIRED" },
  );

  const admin = new PolicyEngine({
    accessMode: "admin",
    allowedProjects: ["sandbox"],
    http,
  });
  assert.deepEqual(
    admin.evaluate({
      project: "sandbox",
      operation: "mutation",
      action: "destroy_service",
      risk: "critical",
    }),
    { allowed: true, code: "ALLOWED" },
  );

  assert.equal(
    admin.assertRequestUrl("https://panel.example.com/api/trpc").origin,
    "https://panel.example.com",
  );
  assert.throws(
    () => admin.assertRequestUrl("https://other.example.com/api/trpc"),
    PolicyError,
  );
  assert.throws(
    () => createHttpClientSecurityPolicy("https://panel.example.com/api"),
    PolicyError,
  );
  assert.throws(
    () => new PolicyEngine({ allowedProjects: ["*"], http }),
    PolicyError,
  );
});

test("environment secret provider resolves only env-backed references without serialization", () => {
  const registry = new SecretRegistry();
  const provider = new EnvSecretProvider({
    env: {
      EASYPANEL_TOKEN: PANEL_TOKEN,
      EASYPANEL_SECRET_DATABASE_PASSWORD: "database-password-secret",
    },
    registry,
  });

  assert.equal(provider.getPanelToken(), PANEL_TOKEN);
  assert.equal(provider.resolve("DATABASE_PASSWORD"), "database-password-secret");
  assert.equal(
    registry.redactText(`token=${PANEL_TOKEN}; password=database-password-secret`),
    "token=[REDACTED]; password=[REDACTED]",
  );
  assert.equal(JSON.stringify(provider), "{}");

  assert.throws(
    () => provider.resolve("literal:do-not-accept"),
    SecretProviderError,
  );
  assert.throws(() => provider.resolve("MISSING"), SecretProviderError);
  assert.throws(
    () =>
      new EnvSecretProvider({
        env: { EASYPANEL_SECRET_TOO_SHORT: "1" },
      }).resolve("TOO_SHORT"),
    SecretProviderError,
  );
  assert.throws(
    () =>
      new EnvSecretProvider({
        env: { EASYPANEL_SECRET_TOO_LARGE: "x".repeat(8_193) },
      }).resolve("TOO_LARGE"),
    SecretProviderError,
  );
});

test("deploy webhook sink rejects multiline and control-bearing credentials", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-webhook-sink-"));
  const sink = new FileWebhookSecretSink(directory);
  try {
    await sink.assertReady();
    assert.deepEqual(await readdir(directory), []);
    const reservation = await sink.reserve("sandbox", "api");
    const reserved = (await readdir(directory)).filter((name) => name.endsWith(".tmp"));
    assert.equal(reserved.length, 1);
    assert.equal((await stat(join(directory, reserved[0] as string))).size, 8_193);
    await reservation.abort();
    assert.deepEqual(await readdir(directory), []);

    for (const invalid of [
      "short",
      "valid-looking-token-but-has\nnewline",
      "valid-looking-token-but-has\rreturn",
      "valid-looking-token-but-has\u0007control",
    ]) {
      await assert.rejects(sink.store("sandbox", "api", invalid));
      assert.deepEqual(await readdir(directory), []);
    }

    const first = "first-valid-webhook-token-value";
    const second = "second-valid-webhook-token-value";
    const destination = join(directory, "sandbox--api.deploy-webhook");
    await sink.store("sandbox", "api", first);
    await assert.rejects(sink.store("sandbox", "api", second));
    assert.equal(await readFile(destination, "utf8"), `${first}\n`);
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit is fixed-schema JSONL, strips payloads, hashes opaque keys, and stays 0600", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-audit-"));
  const path = join(directory, "audit.jsonl");
  const secret = "secret-that-cannot-enter-the-audit";
  const idempotencyKey = "raw-idempotency-key";

  try {
    const audit = new JsonlAuditLog({
      path,
      now: () => new Date("2026-07-11T12:00:00.000Z"),
    });
    const input = {
      actor: "mcp-user",
      action: "apply-plan",
      outcome: "succeeded",
      target: { project: "sandbox", service: "api" },
      planHash: "c".repeat(64),
      idempotencyKey,
      changed: true,
      approvedBy: "security-reviewer",
      confirmedBy: "independent-confirmer",
      plannedActions: ["deploy_service"],
      appliedActions: ["deploy_service"],
      deploymentId: "deployment-safe-id",
      actionId: "lifecycle-safe-id",
      payload: { token: secret, responseBody: secret },
    } as AuditEventInput & { payload: unknown };

    await audit.append(input);

    const contents = await readFile(path, "utf8");
    assert.equal(contents.endsWith("\n"), true);
    assert.equal(contents.includes(secret), false);
    assert.equal(contents.includes(idempotencyKey), false);
    assert.equal(contents.includes("payload"), false);
    assert.equal(contents.includes("responseBody"), false);

    const event = JSON.parse(contents.trim()) as Record<string, unknown>;
    assert.equal(event.schemaVersion, 1);
    assert.match(String(event.idempotencyKeyHash), /^[a-f0-9]{64}$/);
    assert.deepEqual(event.target, { project: "sandbox", service: "api" });
    assert.equal(event.approvedBy, "security-reviewer");
    assert.equal(event.confirmedBy, "independent-confirmer");
    assert.deepEqual(event.plannedActions, ["deploy_service"]);
    assert.deepEqual(event.appliedActions, ["deploy_service"]);
    assert.equal(event.deploymentId, "deployment-safe-id");
    assert.equal(event.actionId, "lifecycle-safe-id");

    const metadata = await stat(path);
    assert.equal(metadata.mode & 0o777, 0o600);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("serialized audit writes preserve validated public attribution despite value collisions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-audit-scope-"));
  const path = join(directory, "audit.jsonl");
  const registry = new SecretRegistry();
  registry.add("permanent-audit-redaction-secret");
  registry.sealBase();
  const audit = new JsonlAuditLog({ path });
  const scopedProjects = ["first-project-secret", "second-project-secret"];

  try {
    await Promise.all(
      scopedProjects.map((project) =>
        registry.runScoped(async () => {
          registry.add(project);
          await Promise.resolve();
          await audit.append({
            actor: "scope-tester",
            action: "scope-query",
            outcome: "denied",
            target: { project },
          });
        }),
      ),
    );

    const contents = await readFile(path, "utf8");
    for (const project of scopedProjects) assert.equal(contents.includes(project), true);
    const events = contents.trim().split("\n").map(
      (line) => JSON.parse(line) as { target: { project: string } },
    );
    assert.equal(events.length, 2);
    assert.deepEqual(
      events.map((event) => event.target.project).sort(),
      [...scopedProjects].sort(),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit log fails closed at its configured retention boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-audit-cap-"));
  const path = join(directory, "audit.jsonl");
  try {
    await writeFile(path, "x".repeat(1_024), { mode: 0o600 });
    const audit = new JsonlAuditLog({ path, maxBytes: 1_024 });
    await assert.rejects(
      audit.append({ actor: "tester", action: "query", outcome: "denied" }),
      (error: unknown) =>
        Boolean(
          error &&
            typeof error === "object" &&
            "code" in error &&
            error.code === "AUDIT_WRITE_FAILED",
        ),
    );
    assert.equal((await stat(path)).size, 1_024);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit and approval storage reject symlinked directories and hardlinked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "easypanel-mcp-links-"));
  const real = join(root, "real");
  const linked = join(root, "linked");
  await mkdir(real, { mode: 0o700 });
  await symlink(real, linked);

  try {
    const audit = new JsonlAuditLog({ path: join(linked, "audit.jsonl") });
    await assert.rejects(
      audit.append({ actor: "tester", action: "query", outcome: "denied" }),
    );

    const approvals = new ExternalApprovalStore({
      directory: linked,
      key: "approval-signing-key-material".repeat(2),
    });
    await assert.rejects(
      approvals.create({
        planHash: "8".repeat(64),
        purpose: "approval",
        action: "apply_service",
        project: "sandbox",
        service: "api",
        approver: "security-reviewer",
      }),
    );

    const privateDirectory = join(root, "private");
    await mkdir(privateDirectory, { mode: 0o700 });
    const original = join(privateDirectory, "original");
    const auditPath = join(privateDirectory, "audit.jsonl");
    await writeFile(original, "", { mode: 0o600 });
    await link(original, auditPath);
    const hardlinkedAudit = new JsonlAuditLog({ path: auditPath });
    await assert.rejects(
      hardlinkedAudit.append({ actor: "tester", action: "query", outcome: "denied" }),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("mutation runtime lock rejects a second local process slot until released", async () => {
  const root = await mkdtemp(join(tmpdir(), "easypanel-mcp-runtime-lock-"));
  const path = join(root, "state", "runtime.lock");
  const first = await SingleInstanceLock.acquire(path);
  try {
    await assert.rejects(SingleInstanceLock.acquire(path));
  } finally {
    await first.release();
  }
  const second = await SingleInstanceLock.acquire(path);
  await second.release();
  await rm(root, { recursive: true, force: true });
});

test("an echoed approval instruction cannot authorize a plan without an external file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-approval-"));
  const plan = newPlan({ planHash: "d".repeat(64) });
  const approvals = new ExternalApprovalStore({
    directory,
    key: "approval-signing-key-material".repeat(2),
    ttlMs: 30_000,
  });

  try {
    const instruction = approvals.instruction(plan);
    assert.equal(instruction.includes(plan.planHash), true);
    assert.equal(instruction.includes("--project sandbox"), true);
    assert.equal(instruction.includes("--service api"), true);

    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_REQUIRED"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("external approval files are signed, target-bound, one-time, and private", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-approval-"));
  const plan = newPlan({
    planHash: "e".repeat(64),
    action: "destroy_service",
    risk: "critical",
  });
  const approvals = new ExternalApprovalStore({
    directory,
    key: "approval-signing-key-material".repeat(2),
    ttlMs: 30_000,
  });

  try {
    assert.equal(approvalActionForPlan(plan), "destroy_service");

    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: "destroy_service",
      project: plan.target.project,
      service: "worker",
      approver: "security-reviewer",
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_INVALID"),
    );

    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: "apply_service",
      approver: "security-reviewer",
      ...plan.target,
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_INVALID"),
    );

    await approvals.create({
      planHash: "9".repeat(64),
      purpose: "approval",
      action: "destroy_service",
      approver: "security-reviewer",
      ...plan.target,
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_REQUIRED"),
    );

    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: "destroy_service",
      approver: "security-reviewer",
      ...plan.target,
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("CONFIRMATION_REQUIRED"),
    );

    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: "destroy_service",
      approver: "same-reviewer",
      ...plan.target,
    });
    await approvals.create({
      planHash: plan.planHash,
      purpose: "confirmation",
      action: "destroy_service",
      approver: "same-reviewer",
      ...plan.target,
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_INVALID"),
    );

    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: "destroy_service",
      approver: "security-reviewer",
      ...plan.target,
    });
    await approvals.create({
      planHash: plan.planHash,
      purpose: "confirmation",
      action: "destroy_service",
      approver: "independent-confirmer",
      ...plan.target,
    });
    const approvalPath = join(directory, `${plan.planHash}.approval.json`);
    const confirmationPath = join(directory, `${plan.planHash}.confirmation.json`);
    const [directoryMetadata, fileMetadata, confirmationMetadata, contents] = await Promise.all([
      stat(directory),
      stat(approvalPath),
      stat(confirmationPath),
      readFile(approvalPath, "utf8"),
    ]);
    assert.equal(directoryMetadata.mode & 0o777, 0o700);
    assert.equal(fileMetadata.mode & 0o777, 0o600);
    assert.equal(confirmationMetadata.mode & 0o777, 0o600);
    assert.equal(contents.includes("signature"), true);
    assert.equal(contents.includes("approval-signing-key-material"), false);

    assert.deepEqual(await approvals.consume(plan), {
      approvedBy: "security-reviewer",
      confirmedBy: "independent-confirmer",
    });
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_REQUIRED"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("external approval files expire closed and are consumed even on rejection", async () => {
  const directory = await mkdtemp(join(tmpdir(), "easypanel-mcp-approval-"));
  let now = Date.parse("2026-07-11T12:00:00.000Z");
  const plan = newPlan({ planHash: "2".repeat(64) });
  const approvals = new ExternalApprovalStore({
    directory,
    key: "approval-signing-key-material".repeat(2),
    ttlMs: 30_000,
    now: () => new Date(now),
  });

  try {
    await approvals.create({
      planHash: plan.planHash,
      purpose: "approval",
      action: approvalActionForPlan(plan),
      approver: "security-reviewer",
      ...plan.target,
    });
    now += 30_001;
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_EXPIRED"),
    );
    await assert.rejects(
      approvals.consume(plan),
      expectApprovalError("APPROVAL_REQUIRED"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("completed plans replay idempotently and expired unapplied plans cannot execute", () => {
  let now = Date.parse("2026-07-11T12:00:00.000Z");
  const store = new PlanStore({
    ttlMs: 1_000,
    replayTtlMs: 60_000,
    now: () => new Date(now),
  });
  const saved = store.save(newPlan({ planHash: "f".repeat(64) }));
  const duplicateWhileActive = store.save(newPlan({ planHash: "e".repeat(64) }));
  assert.equal(duplicateWhileActive.planHash, saved.planHash);

  const claim = store.claim(saved.planHash);
  assert.equal(claim.kind, "execute");

  const result: ApplyResult = {
    planHash: saved.planHash,
    changed: true,
    idempotentReplay: false,
    appliedActions: ["deploy_service"],
    verified: true,
    target: saved.target,
  };
  const completed = store.complete(result);
  assert.equal(completed.idempotentReplay, false);

  const nextGeneration = store.save(newPlan({ planHash: "d".repeat(64) }));
  assert.equal(nextGeneration.planHash, "d".repeat(64));
  assert.notEqual(nextGeneration.planHash, saved.planHash);

  const replay = store.claim(saved.planHash);
  assert.equal(replay.kind, "replay");
  if (replay.kind === "replay") {
    assert.equal(replay.result.idempotentReplay, true);
    assert.equal(replay.result.changed, false);
    assert.deepEqual(replay.result.appliedActions, []);
    assert.equal(replay.result.planHash, saved.planHash);
    assert.deepEqual(replay.result.target, saved.target);
  }

  const expiring = store.save(newPlan({
    planHash: "1".repeat(64),
    intentHash: "1".repeat(64),
    service: "worker",
  }));
  now += 1_001;
  assert.throws(
    () => store.claim(expiring.planHash),
    expectPlanError("PLAN_EXPIRED"),
  );
});

test("completed no-change generations never consume active quota and replay eviction is safe", () => {
  const store = new PlanStore({
    ttlMs: 60_000,
    replayTtlMs: 60_000,
    maxEntries: 2,
    maxEntriesPerTarget: 1,
  });
  const hashes = ["6".repeat(64), "7".repeat(64), "8".repeat(64)];

  for (const planHash of hashes) {
    const input = newPlan({ planHash });
    input.actions = [];
    input.noChanges = true;
    input.operation = undefined;
    const saved = store.save(input);
    assert.equal(store.claim(saved.planHash).kind, "execute");
    store.complete({
      planHash: saved.planHash,
      changed: false,
      idempotentReplay: false,
      appliedActions: [],
      verified: true,
      target: saved.target,
    });
  }

  assert.throws(
    () => store.claim(hashes[0] as string),
    expectPlanError("PLAN_NOT_FOUND"),
  );
  assert.equal(store.claim(hashes[1] as string).kind, "replay");
  assert.equal(store.claim(hashes[2] as string).kind, "replay");

  const active = store.save(newPlan({ planHash: "a".repeat(64) }));
  assert.equal(store.claim(active.planHash).kind, "execute");
});

test("uncertain tombstones block the generation and intent without consuming active target capacity", () => {
  const store = new PlanStore({
    ttlMs: 60_000,
    maxEntries: 2,
    maxEntriesPerTarget: 1,
  });
  const uncertain = store.save(newPlan({ planHash: "3".repeat(64) }));
  assert.equal(store.claim(uncertain.planHash).kind, "execute");
  store.invalidate(uncertain.planHash);

  assert.throws(
    () => store.save(newPlan({ planHash: "3".repeat(64) })),
    expectPlanError("PLAN_UNCERTAIN"),
  );
  assert.throws(
    () => store.save(newPlan({ planHash: "5".repeat(64) })),
    expectPlanError("PLAN_UNCERTAIN"),
  );
  assert.throws(
    () => store.get(uncertain.planHash),
    expectPlanError("PLAN_UNCERTAIN"),
  );
  const replacement = store.save(newPlan({
    planHash: "4".repeat(64),
    intentHash: "4".repeat(64),
  }));
  assert.equal(replacement.target.service, "api");
});
