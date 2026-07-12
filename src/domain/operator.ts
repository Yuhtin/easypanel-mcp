import { compareCodePoints, constantTimeEqual } from "../core/canonical-json.js";
import type { JsonlAuditLog } from "../core/audit.js";
import {
  type ApprovalEvidence,
  ExternalApprovalStore,
  PlanCryptography,
} from "../core/external-approval.js";
import { KeyedMutex } from "../core/keyed-mutex.js";
import type { PlanStore } from "../core/plan-store.js";
import { isCriticalPlan } from "../core/risk.js";
import type { PolicyEngine } from "../core/policy.js";
import { safeErrorCode } from "../core/redaction.js";
import type { EasypanelGateway } from "../gateway/gateway.js";
import type { SecretProvider } from "../secrets/env-secret-provider.js";
import type { WebhookSecretSink } from "../secrets/webhook-secret-sink.js";
import { EnvDocument } from "./env-document.js";
import {
  operationPrecondition,
  prepareOperationPlan,
  type PlannedOperation,
} from "./operation-planner.js";
import {
  prepareServicePlan,
  publicSnapshot,
  snapshotPrecondition,
} from "./planner.js";
import { ServiceSpecSchema, TargetSchema, type ServiceSpec } from "./schemas.js";
import type {
  ApplyResult,
  CapabilitySnapshot,
  DeploymentSummary,
  InternalServiceSnapshot,
  PlanAction,
  PublicPlan,
  PublicServiceSnapshot,
  StoredPlan,
} from "./types.js";

export interface EasypanelOperatorOptions {
  gateway: EasypanelGateway;
  policy: PolicyEngine;
  plans: PlanStore;
  approvals: ExternalApprovalStore;
  cryptography: PlanCryptography;
  secrets: SecretProvider;
  webhookSink?: WebhookSecretSink;
  audit: JsonlAuditLog;
  actor: string;
  now?: () => Date;
  applyDeadlineMs?: number;
}

interface ExecutionEvidence {
  deploymentId?: string;
  deploymentRequestId?: string;
  lifecycleActionId?: string;
  lifecycleRequestId?: string;
  databaseCredentialAccepted?: true;
}

export class EasypanelOperator {
  readonly #gateway: EasypanelGateway;
  readonly #policy: PolicyEngine;
  readonly #plans: PlanStore;
  readonly #approvals: ExternalApprovalStore;
  readonly #crypto: PlanCryptography;
  readonly #secrets: SecretProvider;
  readonly #webhookSink?: WebhookSecretSink;
  readonly #audit: JsonlAuditLog;
  readonly #actor: string;
  readonly #now: () => Date;
  readonly #applyDeadlineMs: number;
  readonly #locks = new KeyedMutex();
  #mutationsHalted = false;

  constructor(options: EasypanelOperatorOptions) {
    this.#gateway = options.gateway;
    this.#policy = options.policy;
    this.#plans = options.plans;
    this.#approvals = options.approvals;
    this.#crypto = options.cryptography;
    this.#secrets = options.secrets;
    this.#webhookSink = options.webhookSink;
    this.#audit = options.audit;
    this.#actor = options.actor;
    this.#now = options.now ?? (() => new Date());
    if (
      options.applyDeadlineMs !== undefined &&
      (!Number.isSafeInteger(options.applyDeadlineMs) ||
        options.applyDeadlineMs < 10 ||
        options.applyDeadlineMs > 600_000)
    ) {
      throw codedError("INVALID_CONFIGURATION", "Apply deadline is invalid");
    }
    this.#applyDeadlineMs = options.applyDeadlineMs ?? 180_000;
  }

  async capabilities(): Promise<{
    instanceId: string;
    instanceLabel: string;
    flavor: string;
    version: string;
    profile: string;
    features: string[];
    accessMode: string;
    allowedProjects: readonly string[];
  }> {
    const capability = await this.#gateway.refreshCapabilities();
    if (this.#webhookSink) await this.#webhookSink.assertReady();
    return {
      instanceId: capability.instanceId,
      instanceLabel: capability.instanceLabel,
      flavor: capability.flavor,
      version: capability.version,
      profile: capability.profile,
      features: [...capability.features]
        .filter((feature) => feature !== "rotate_deploy_webhook" || this.#webhookSink !== undefined)
        .sort(),
      accessMode: this.#policy.accessMode,
      allowedProjects: this.#policy.allowedProjects,
    };
  }

  async listProjects(): Promise<{ projects: string[] }> {
    const inventory = await this.#gateway.listInventory();
    const allowed = new Set(this.#policy.allowedProjects);
    return {
      projects: inventory.projects
        .map((entry) => entry.name)
        .filter((name) => allowed.has(name))
        .sort(),
    };
  }

  async listServices(project: string): Promise<{
    project: string;
    services: Array<{ name: string; kind: string; enabled: boolean }>;
  }> {
    await this.#assertQueryAllowed(project, undefined, "list_services");
    const inventory = await this.#gateway.listInventory();
    return {
      project,
      services: inventory.services
        .filter((entry) => entry.project === project)
        .map(({ name, kind, enabled }) => ({ name, kind, enabled }))
        .sort((left, right) => compareCodePoints(left.name, right.name)),
    };
  }

  async inspectService(
    project: string,
    service: string,
  ): Promise<PublicServiceSnapshot> {
    await this.#assertQueryAllowed(project, service, "inspect_service");
    return publicSnapshot(await this.#gateway.inspectService(project, service));
  }

  async listDeployments(project: string, service: string): Promise<DeploymentSummary[]> {
    await this.#assertQueryAllowed(project, service, "list_deployments");
    return this.#gateway.listDeployments(project, service);
  }

  async getDeploymentStatus(
    id: string,
    project: string,
    service: string,
  ): Promise<DeploymentSummary | null> {
    await this.#assertQueryAllowed(project, service, "get_deployment_status");
    const known = await this.#gateway.listDeployments(project, service);
    if (!known.some((deployment) => deployment.id === id)) return null;
    const deployment = await this.#gateway.getDeployment(id);
    if (
      deployment &&
      (deployment.project !== project || deployment.service !== service)
    ) {
      const error = new Error("Deployment is outside the requested project");
      Object.defineProperty(error, "code", { value: "PROJECT_DENIED" });
      throw error;
    }
    return deployment;
  }

  async getSanitizedLogs(project: string, service: string, _maxLines: number): Promise<{
    trust: "untrusted";
    source: "policy";
    content: string;
  }> {
    await this.#assertQueryAllowed(project, service, "get_sanitized_logs");
    return {
      trust: "untrusted",
      source: "policy",
      content: "[UNTRUSTED_LOG] Deployment log content is disabled by security policy",
    };
  }

  async checkServiceHealth(project: string, service: string): Promise<{
    project: string;
    service: string;
    exists: boolean;
    enabled: boolean;
    status: "running" | "stopped" | "deploying" | "error" | "unknown";
    health: "healthy" | "unhealthy" | "unknown";
    readiness: "ready" | "not_ready" | "unknown";
  }> {
    await this.#assertQueryAllowed(project, service, "check_service_health");
    const snapshot = await this.#gateway.inspectService(project, service);
    const status = normalizePublicStatus(snapshot.status);
    const health = snapshot.health ?? "unknown";
    const readiness =
      !snapshot.exists ||
      !snapshot.enabled ||
      status === "stopped" ||
      status === "error" ||
      health === "unhealthy"
        ? "not_ready"
        : snapshot.readiness ?? "unknown";
    return {
      project,
      service,
      exists: snapshot.exists,
      enabled: snapshot.enabled,
      status,
      health,
      readiness,
    };
  }

  async planService(untrustedSpec: unknown): Promise<PublicPlan> {
    const parsed = ServiceSpecSchema.parse(untrustedSpec);
    const spec = parsed as ServiceSpec;
    await this.#assertQueryAllowed(spec.project, spec.service, "plan_service");
    const [capability, inventory] = await Promise.all([
      this.#gateway.refreshCapabilities(),
      this.#gateway.listInventory(),
    ]);
    const projectExists = inventory.projects.some((entry) => entry.name === spec.project);
    const snapshot = await this.#gateway.inspectService(spec.project, spec.service, spec.kind);
    assertProjectSnapshotConsistency(projectExists, snapshot.exists);
    const draft = prepareServicePlan({
      spec,
      projectExists,
      snapshot,
      features: capability.features,
      secrets: this.#secrets,
      cryptography: this.#crypto,
      capabilityHash: capabilityPrecondition(capability, this.#crypto),
    });
    const approval = this.#approvals.instruction(draft, "approval");
    const stored = this.#plans.save({
      ...draft,
      approval,
      ...(isCriticalPlan(draft)
        ? { confirmation: this.#approvals.instruction(draft, "confirmation") }
        : {}),
    });
    await this.#audit.append({
      actor: this.#actor,
      action: "plan_service",
      outcome: "allowed",
      target: stored.target,
      planHash: stored.planHash,
      changed: !stored.noChanges,
      plannedActions: stored.actions.map((action) => action.type),
    });
    return toPublicPlan(stored);
  }

  async planDestroy(project: string, service: string): Promise<PublicPlan> {
    await this.#assertQueryAllowed(project, service, "plan_destroy");
    const snapshot = await this.#gateway.inspectService(project, service);
    return this.planService({
      project,
      service,
      kind: snapshot.kind,
      ensure: "absent",
    });
  }

  async planOperation(
    operation: PlannedOperation,
    project: string,
    service: string,
  ): Promise<PublicPlan> {
    TargetSchema.parse({ project, service });
    await this.#assertQueryAllowed(project, service, `plan_${operation}`);
    if (operation === "rotate_deploy_webhook" && !this.#webhookSink) {
      throw codedError("FEATURE_UNSUPPORTED", "A secure webhook secret sink is not configured");
    }
    if (operation === "rotate_deploy_webhook") {
      await this.#webhookSink!.assertReady();
    }
    const [capability, snapshot] = await Promise.all([
      this.#gateway.refreshCapabilities(),
      this.#gateway.inspectService(project, service, "app"),
    ]);
    const operationState = await this.#operationState(operation, project, service);
    const draft = prepareOperationPlan({
      operation,
      snapshot,
      state: operationState,
      features: capability.features,
      cryptography: this.#crypto,
      capabilityHash: capabilityPrecondition(capability, this.#crypto),
    });
    const approval = this.#approvals.instruction(draft, "approval");
    const stored = this.#plans.save({
      ...draft,
      approval,
      ...(isCriticalPlan(draft)
        ? { confirmation: this.#approvals.instruction(draft, "confirmation") }
        : {}),
    });
    await this.#audit.append({
      actor: this.#actor,
      action: `plan_${operation}`,
      outcome: "allowed",
      target: stored.target,
      planHash: stored.planHash,
      changed: !stored.noChanges,
      plannedActions: stored.actions.map((action) => action.type),
    });
    return toPublicPlan(stored);
  }

  async applyPlan(
    planHash: string,
    expected?: {
      project?: string;
      service?: string;
      action?: PlanAction["type"];
      forbidCritical?: boolean;
      requireServiceSpec?: boolean;
    },
  ): Promise<ApplyResult> {
    if (this.#mutationsHalted) {
      throw codedError(
        "PLAN_UNCERTAIN",
        "Mutations are halted after an apply exceeded its safety deadline",
      );
    }
    const preview = this.#plans.get(planHash);
    if (!preview) {
      const error = new Error("Plan not found or expired");
      Object.defineProperty(error, "code", { value: "PLAN_NOT_FOUND" });
      throw error;
    }
    if (
      expected &&
      ((expected.project !== undefined && preview.target.project !== expected.project) ||
        (expected.service !== undefined && preview.target.service !== expected.service) ||
        (expected.action && !planMatchesExpectedAction(preview, expected.action)) ||
        (expected.forbidCritical && isCriticalPlan(preview)) ||
        (expected.requireServiceSpec &&
          (preview.spec === undefined ||
            preview.operation !== undefined ||
            preview.spec.ensure !== "present")))
    ) {
      const error = new Error("Plan target or operation does not match the tool call");
      Object.defineProperty(error, "code", { value: "PLAN_TARGET_MISMATCH" });
      await this.#auditDenied(preview, error);
      throw error;
    }

    let cancelled = false;
    const assertActive = (): void => {
      if (cancelled || this.#mutationsHalted) {
        throw codedError("PLAN_UNCERTAIN", "Mutation admission was cancelled");
      }
    };
    const execution = this.#locks.run(
      `${preview.target.project}/${preview.target.service}`,
      async () => {
      assertActive();
      const current = this.#plans.get(planHash);
      if (!current) throw codedError("PLAN_NOT_FOUND", "Plan not found or expired");
      if (current.result) {
        const claim = this.#plans.claim(planHash);
        if (claim.kind !== "replay") throw codedError("PLAN_INVALID", "Invalid replay state");
        await this.#audit.append({
          actor: this.#actor,
          action: "apply_plan",
          outcome: "replayed",
          target: current.target,
          planHash,
          idempotencyKey: planHash,
          changed: false,
          plannedActions: current.actions.map((action) => action.type),
          appliedActions: [],
        });
        return claim.result;
      }

      try {
        for (const action of current.actions) {
          this.#policy.assertAllowed({
            project: current.target.project,
            operation: "mutation",
            action: action.type,
            risk: action.risk,
          });
        }
      } catch (error: unknown) {
        await this.#auditDenied(current, error);
        throw error;
      }

      let approvalEvidence: ApprovalEvidence | undefined;
      if (!current.noChanges) {
        try {
          approvalEvidence = await this.#approvals.consume(current);
        } catch (error: unknown) {
          await this.#auditDenied(current, error);
          throw error;
        }
      }
      assertActive();
      const claim = this.#plans.claim(planHash);
      if (claim.kind === "replay") return claim.result;
      const plan = claim.plan;
      const startedAt = this.#now().getTime();
      let auditId = "";
      let mutationAttempted = false;
      const executionEvidence: ExecutionEvidence = {};
      const appliedActions: PlanAction["type"][] = [];
      try {
        await this.#assertPreconditions(plan);
        assertActive();
        const resolvedSecrets = this.#resolvePlanSecrets(plan);
        const started = await this.#audit.append({
          actor: this.#actor,
          action: "apply_plan",
          outcome: "started",
          target: plan.target,
          planHash,
          idempotencyKey: planHash,
          changed: !plan.noChanges,
          ...approvalEvidence,
          plannedActions: plan.actions.map((action) => action.type),
          appliedActions: [],
        });
        auditId = started.auditId;
        assertActive();

        for (const action of plan.actions) {
          assertActive();
          mutationAttempted = true;
          const changed = await this.#executeAction(
              plan,
              action,
              auditId,
              resolvedSecrets,
              executionEvidence,
              assertActive,
            );
          assertActive();
          if (changed) {
            appliedActions.push(action.type);
          }
          await this.#audit.append({
            actor: this.#actor,
            action: `apply_${action.type}`,
            outcome: "succeeded",
            target: plan.target,
            planHash,
            idempotencyKey: planHash,
            changed,
            plannedActions: [action.type],
            appliedActions: changed ? [action.type] : [],
            ...(action.type === "deploy_service" && executionEvidence.deploymentId
              ? { deploymentId: executionEvidence.deploymentId }
              : {}),
            ...(isLifecycleAction(action.type) && executionEvidence.lifecycleActionId
              ? { actionId: executionEvidence.lifecycleActionId }
              : {}),
            ...approvalEvidence,
          });
        }
        assertActive();
        await this.#verify(plan, resolvedSecrets, executionEvidence, assertActive);
        assertActive();
        const result: ApplyResult = {
          planHash,
          changed: appliedActions.length > 0,
          idempotentReplay: false,
          appliedActions,
          ...(executionEvidence.deploymentId
            ? { deploymentId: executionEvidence.deploymentId }
            : {}),
          ...(executionEvidence.lifecycleActionId
            ? { actionId: executionEvidence.lifecycleActionId }
            : {}),
          verified: true,
          target: structuredClone(plan.target),
        };
        const completed = this.#plans.complete(result);
        await this.#audit.append({
          actor: this.#actor,
          action: "apply_plan",
          outcome: "succeeded",
          target: plan.target,
          planHash,
          idempotencyKey: planHash,
          durationMs: Math.max(0, this.#now().getTime() - startedAt),
          changed: result.changed,
          ...approvalEvidence,
          plannedActions: plan.actions.map((action) => action.type),
          appliedActions,
          ...(executionEvidence.deploymentId
            ? { deploymentId: executionEvidence.deploymentId }
            : {}),
          ...(executionEvidence.lifecycleActionId
            ? { actionId: executionEvidence.lifecycleActionId }
            : {}),
        });
        return completed;
      } catch (error: unknown) {
        // A timeout or verification error can happen after the upstream commit.
        // Reusing this plan could duplicate a deployment or a partial apply.
        if (!this.#plans.get(planHash)?.result) {
          if (mutationAttempted) this.#plans.invalidate(planHash);
          else this.#plans.release(planHash);
        }
        await this.#audit
          .append({
            actor: this.#actor,
            action: "apply_plan",
            outcome: "failed",
            target: plan.target,
            planHash,
            idempotencyKey: planHash,
            errorCode: safeErrorCode(error),
            durationMs: Math.max(0, this.#now().getTime() - startedAt),
            changed: auditId !== "" && plan.actions.length > 0,
            ...approvalEvidence,
            plannedActions: plan.actions.map((action) => action.type),
            appliedActions,
            ...(executionEvidence.deploymentId
              ? { deploymentId: executionEvidence.deploymentId }
              : {}),
            ...(executionEvidence.lifecycleActionId
              ? { actionId: executionEvidence.lifecycleActionId }
              : {}),
          })
          .catch(() => undefined);
        throw error;
      }
      },
    );
    return this.#withApplyDeadline(execution, () => {
      cancelled = true;
      this.#mutationsHalted = true;
    });
  }

  #withApplyDeadline<T>(operation: Promise<T>, onTimeout: () => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      let timedOut = false;
      const timer = setTimeout(() => {
        if (settled) return;
        timedOut = true;
        onTimeout();
      }, this.#applyDeadlineMs);
      operation.then(
        (value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (timedOut) {
            reject(codedError("PLAN_UNCERTAIN", "Apply safety deadline exceeded"));
          } else {
            resolve(value);
          }
        },
        (error: unknown) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(
            timedOut
              ? codedError("PLAN_UNCERTAIN", "Apply safety deadline exceeded")
              : error,
          );
        },
      );
    });
  }

  async #assertPreconditions(plan: StoredPlan): Promise<void> {
    const capability = await this.#gateway.refreshCapabilities();
    const actualCapabilityHash = capabilityPrecondition(capability, this.#crypto);
    if (!constantTimeEqual(actualCapabilityHash, plan.capabilityHash)) {
      throw codedError(
        "PRECONDITION_CHANGED",
        "Easypanel capabilities changed; create a new plan",
      );
    }
    const snapshot = await this.#gateway.inspectService(
      plan.target.project,
      plan.target.service,
      plan.spec?.kind ?? "app",
    );
    if (plan.spec) {
      const inventory = await this.#gateway.listInventory();
      const projectExists = inventory.projects.some((entry) => entry.name === plan.target.project);
      assertProjectSnapshotConsistency(projectExists, snapshot.exists);
      const actual = snapshotPrecondition(projectExists, snapshot, this.#crypto);
      if (!constantTimeEqual(actual, plan.preconditionHash)) {
        throw codedError("PRECONDITION_CHANGED", "Service state changed; create a new plan");
      }
      return;
    }

    const state = await this.#operationState(plan.operation!, plan.target.project, plan.target.service);
    const actual = operationPrecondition(snapshot, state, this.#crypto);
    if (!constantTimeEqual(actual, plan.preconditionHash)) {
      throw codedError("PRECONDITION_CHANGED", "Operation state changed; create a new plan");
    }
  }

  async #executeAction(
    plan: StoredPlan,
    action: PlanAction,
    auditId: string,
    resolvedSecrets: ReadonlyMap<string, string>,
    executionEvidence: ExecutionEvidence,
    assertActive: () => void,
  ): Promise<boolean> {
    const { project, service } = plan.target;
    const context = { auditId };
    const spec = plan.spec;
    assertActive();
    switch (action.type) {
      case "create_project":
        await this.#gateway.createProject(project, context);
        return true;
      case "create_service":
        const evidence = await this.#gateway.createService(
          project,
          service,
          spec!.kind,
          {
            ...(spec!.database
              ? { password: requiredResolvedSecret(resolvedSecrets, spec!.database.initialPassword.name) }
              : {}),
          },
          context,
        );
        if (evidence.databaseCredentialAccepted) {
          executionEvidence.databaseCredentialAccepted = true;
        }
        return true;
      case "update_source":
        await this.#gateway.updateSource(project, service, spec!.source!, context);
        return true;
      case "merge_environment": {
        const current = await this.#gateway.inspectService(project, service, "app");
        assertActive();
        const env = EnvDocument.parse(current.envDocument);
        for (const [name, assignment] of Object.entries(spec!.environment!.merge)) {
          if (assignment.from === "secret") {
            const value = requiredResolvedSecret(resolvedSecrets, assignment.name);
            env.set(name, value);
          } else {
            env.set(name, assignment.value);
          }
        }
        for (const name of spec!.environment!.remove) env.remove(name);
        if (env.serialize() === current.envDocument) return false;
        await this.#gateway.updateEnvironment(project, service, env.serialize(), context);
        return true;
      }
      case "update_resources":
        await this.#gateway.updateResources(project, service, spec!.resources!, context);
        return true;
      case "update_deploy":
        await this.#gateway.updateDeploy(project, service, spec!.deploy!, context);
        return true;
      case "add_domain": {
        const host = domainFromAction(action);
        const domain = spec!.domains!.find((entry) => entry.host === host);
        if (!domain) throw codedError("PLAN_INVALID", "Domain payload is missing from plan");
        await this.#gateway.addDomain(project, service, domain, context);
        return true;
      }
      case "remove_domain":
        await this.#gateway.removeDomain(project, service, domainFromAction(action), context);
        return true;
      case "update_healthcheck":
        await this.#gateway.updateHealthcheck(project, service, spec!.healthcheck ?? null, context);
        return true;
      case "destroy_service":
        await this.#gateway.destroyService(project, service, spec!.kind, context);
        return true;
      case "deploy_service":
        executionEvidence.deploymentId = await this.#gateway.deployService(
          project,
          service,
          context,
        );
        executionEvidence.deploymentRequestId = auditId;
        return true;
      case "start_service":
        executionEvidence.lifecycleActionId = await this.#gateway.startService(
          project,
          service,
          context,
        );
        executionEvidence.lifecycleRequestId = auditId;
        return true;
      case "stop_service":
        executionEvidence.lifecycleActionId = await this.#gateway.stopService(
          project,
          service,
          context,
        );
        executionEvidence.lifecycleRequestId = auditId;
        return true;
      case "restart_service":
        executionEvidence.lifecycleActionId = await this.#gateway.restartService(
          project,
          service,
          context,
        );
        executionEvidence.lifecycleRequestId = auditId;
        return true;
      case "rotate_deploy_webhook":
        {
          const reservation = await this.#webhookSink!.reserve(project, service);
          try {
            assertActive();
            const value = await this.#gateway.rotateDeployWebhook(
              project,
              service,
              context,
            );
            await reservation.commit(value);
            return true;
          } catch (error: unknown) {
            await reservation.abort().catch(() => undefined);
            throw error;
          }
        }
    }
  }

  async #verify(
    plan: StoredPlan,
    resolvedSecrets: ReadonlyMap<string, string>,
    executionEvidence: ExecutionEvidence,
    assertActive: () => void,
  ): Promise<void> {
    assertActive();
    if (plan.spec) {
      if (
        plan.spec.kind !== "app" &&
        plan.spec.database !== undefined &&
        plan.actions.some((action) => action.type === "create_service") &&
        executionEvidence.databaseCredentialAccepted !== true
      ) {
        throw codedError(
          "VERIFY_FAILED",
          "Database bootstrap credential acceptance was not acknowledged",
        );
      }
      const [capability, inventory, snapshot] = await Promise.all([
        this.#gateway.discover(),
        this.#gateway.listInventory(),
        this.#gateway.inspectService(plan.target.project, plan.target.service, plan.spec.kind),
      ]);
      assertActive();
      const projectExists = inventory.projects.some((entry) => entry.name === plan.target.project);
      assertProjectSnapshotConsistency(projectExists, snapshot.exists);
      const followUp = prepareServicePlan({
        spec: plan.spec,
        projectExists,
        snapshot,
        features: capability.features,
        secrets: {
          resolve: (name: string) => requiredResolvedSecret(resolvedSecrets, name),
        },
        cryptography: this.#crypto,
        capabilityHash: plan.capabilityHash,
        resolveSecretValues: true,
      });
      if (!followUp.noChanges) {
        throw codedError("VERIFY_FAILED", "Desired state was not reached after apply");
      }
      return;
    }

    if (plan.operation === "deploy") {
      const before = new Set(plan.operationState?.deploymentIds ?? []);
      const deploymentId = executionEvidence.deploymentId;
      const requestId = executionEvidence.deploymentRequestId;
      if (!deploymentId || !requestId || before.has(deploymentId)) {
        throw codedError("VERIFY_FAILED", "The deployment action identifier is invalid");
      }
      for (let attempt = 0; attempt < 30; attempt += 1) {
        assertActive();
        const deployment = await this.#gateway.getDeploymentForRequest(
          deploymentId,
          plan.target.project,
          plan.target.service,
          requestId,
        );
        assertActive();
        if (deployment?.status === "running") return;
        if (deployment?.status === "error" || deployment?.status === "stopped") {
          throw codedError("VERIFY_FAILED", "The deployment action failed");
        }
        if (attempt < 29) {
          await delay(2_000);
          assertActive();
        }
      }
      throw codedError("VERIFY_FAILED", "The deployment action did not complete in time");
    }

    if (
      plan.operation === "start" ||
      plan.operation === "stop" ||
      plan.operation === "restart"
    ) {
      if (plan.actions.length > 0) {
        const actionId = executionEvidence.lifecycleActionId;
        const requestId = executionEvidence.lifecycleRequestId;
        const previousIds = new Set(
          (plan.operationState?.lifecycleActions ?? []).map((action) => action.id),
        );
        if (!actionId || !requestId || previousIds.has(actionId)) {
          throw codedError("VERIFY_FAILED", "The lifecycle action identifier is not fresh");
        }
        let actionSucceeded = false;
        for (let attempt = 0; attempt < 30; attempt += 1) {
          assertActive();
          const status = await this.#gateway.getLifecycleActionStatus(
            actionId,
            plan.target.project,
            plan.target.service,
            plan.operation,
            requestId,
          );
          assertActive();
          if (status === "succeeded") {
            actionSucceeded = true;
            break;
          }
          if (status === "failed") {
            throw codedError("VERIFY_FAILED", "The lifecycle action failed");
          }
          if (attempt < 29) {
            await delay(2_000);
            assertActive();
          }
        }
        if (!actionSucceeded) {
          throw codedError("VERIFY_FAILED", "The lifecycle action did not complete in time");
        }
      }
      for (let attempt = 0; attempt < 10; attempt += 1) {
        assertActive();
        const snapshot = await this.#gateway.inspectService(
          plan.target.project,
          plan.target.service,
          "app",
        );
        assertActive();
        const status = normalizePublicStatus(snapshot.status);
        const reached =
          plan.operation === "stop"
            ? !snapshot.enabled && status === "stopped"
            : snapshot.exists && snapshot.enabled && status === "running";
        if (reached) return;
        if (attempt < 9) {
          await delay(500);
          assertActive();
        }
      }
      throw codedError("VERIFY_FAILED", "The requested runtime state was not observed");
    }

    const before = plan.operationState?.webhookFingerprint;
    const after = await this.#gateway.getDeployWebhookFingerprint(
      plan.target.project,
      plan.target.service,
    );
    assertActive();
    if (!after || (before !== undefined && constantTimeEqual(before, after))) {
      throw codedError("VERIFY_FAILED", "Deploy webhook rotation could not be verified");
    }
  }

  async #operationState(
    operation: PlannedOperation,
    project: string,
    service: string,
  ): Promise<NonNullable<StoredPlan["operationState"]>> {
    if (operation === "deploy") {
      return {
        deploymentIds: (await this.#gateway.listDeployments(project, service)).map(
          (entry) => entry.id,
        ),
      };
    }
    if (operation === "rotate_deploy_webhook") {
      return {
        webhookFingerprint: await this.#gateway.getDeployWebhookFingerprint(project, service),
      };
    }
    return {
      lifecycleActions: (await this.#gateway.listLifecycleActions(project, service)).map(
        ({ id, operation: observedOperation, status }) => ({
          id,
          operation: observedOperation,
          status,
        }),
      ),
    };
  }

  async #auditDenied(plan: StoredPlan, error: unknown): Promise<void> {
    await this.#audit.append({
      actor: this.#actor,
      action: "apply_plan",
      outcome: "denied",
      target: plan.target,
      planHash: plan.planHash,
      idempotencyKey: plan.planHash,
      errorCode: safeErrorCode(error),
      changed: false,
      plannedActions: plan.actions.map((action) => action.type),
      appliedActions: [],
    });
  }

  async #assertQueryAllowed(
    project: string,
    service: string | undefined,
    action: string,
  ): Promise<void> {
    try {
      this.#policy.assertAllowed({ project, operation: "query" });
    } catch (error: unknown) {
      await this.#audit.append({
        actor: this.#actor,
        action,
        outcome: "denied",
        target: { project, ...(service ? { service } : {}) },
        errorCode: safeErrorCode(error),
        changed: false,
      });
      throw error;
    }
  }

  #resolvePlanSecrets(plan: StoredPlan): ReadonlyMap<string, string> {
    const names = new Set<string>();
    if (plan.spec?.database) names.add(plan.spec.database.initialPassword.name);
    for (const assignment of Object.values(plan.spec?.environment?.merge ?? {})) {
      if (assignment.from === "secret") names.add(assignment.name);
    }
    return new Map([...names].sort().map((name) => [name, this.#secrets.resolve(name)]));
  }
}

export function toPublicPlan(plan: StoredPlan): PublicPlan {
  return {
    planHash: plan.planHash,
    target: structuredClone(plan.target),
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    actions: structuredClone(plan.actions),
    noChanges: plan.noChanges,
    approval: plan.noChanges
      ? "No approval is required because this plan contains no changes"
      : plan.approval,
    ...(plan.confirmation ? { confirmation: plan.confirmation } : {}),
  };
}

function domainFromAction(action: PlanAction): string {
  const field = action.changedFields.find((entry) => entry.startsWith("domains."));
  if (!field) throw codedError("PLAN_INVALID", "Domain target is missing from plan");
  return field.slice("domains.".length);
}

function planMatchesExpectedAction(plan: StoredPlan, action: PlanAction["type"]): boolean {
  if (plan.actions.some((entry) => entry.type === action)) return true;
  if (!plan.noChanges) return false;
  if (action === "destroy_service") return plan.spec?.ensure === "absent";
  if (action === "start_service") return plan.operation === "start";
  if (action === "stop_service") return plan.operation === "stop";
  if (action === "restart_service") return plan.operation === "restart";
  return false;
}

function isLifecycleAction(action: PlanAction["type"]): boolean {
  return (
    action === "start_service" ||
    action === "stop_service" ||
    action === "restart_service"
  );
}

function codedError(code: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, "code", { value: code });
  return error;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function requiredResolvedSecret(
  secrets: ReadonlyMap<string, string>,
  name: string,
): string {
  const value = secrets.get(name);
  if (value === undefined) throw codedError("SECRET_NOT_FOUND", "Secret was not resolved");
  return value;
}

function normalizePublicStatus(
  value: string | undefined,
): "running" | "stopped" | "deploying" | "error" | "unknown" {
  return value === "running" ||
    value === "stopped" ||
    value === "deploying" ||
    value === "error"
    ? value
    : "unknown";
}

function assertProjectSnapshotConsistency(
  projectExists: boolean,
  serviceExists: boolean,
): void {
  if (serviceExists && !projectExists) {
    throw codedError(
      "INVENTORY_INCONSISTENT",
      "A service cannot exist outside the discovered project inventory",
    );
  }
}

function capabilityPrecondition(
  capability: CapabilitySnapshot,
  cryptography: PlanCryptography,
): string {
  return cryptography.signPlan({
    purpose: "capability-precondition",
    flavor: capability.flavor,
    version: capability.version,
    profile: capability.profile,
    procedures: [...capability.procedures.entries()].sort(([left], [right]) =>
      compareCodePoints(left, right),
    ),
    features: [...capability.features].sort(),
  });
}
