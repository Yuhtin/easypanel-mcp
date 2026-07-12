import { constants } from "node:fs";
import { open } from "node:fs/promises";

import { z } from "zod";

import { compareCodePoints, sha256 } from "../core/canonical-json.js";
import {
  isSensitiveEnvName,
  SecretRegistry,
} from "../core/redaction.js";
import { EnvDocument } from "../domain/env-document.js";
import {
  DeploySettingsSchema,
  DomainSchema,
  HealthcheckSchema,
  ProjectNameSchema,
  ResourcesSchema,
  ServiceNameSchema,
  SourceSchema,
} from "../domain/schemas.js";
import type {
  DeploySettings,
  Healthcheck,
  Resources,
  ServiceDomain,
  ServiceSource,
} from "../domain/schemas.js";
import type {
  CapabilitySnapshot,
  DeploymentSummary,
  GatewayMutationContext,
  InternalServiceSnapshot,
  Inventory,
  LifecycleActionSummary,
  LifecycleActionStatus,
  LifecycleOperation,
  ProcedureType,
  ServiceHealthStatus,
  ServiceKind,
  ServiceReadiness,
  ServiceRuntimeStatus,
} from "../domain/types.js";
import type { CreateServiceEvidence, EasypanelGateway } from "./gateway.js";
import { PROCEDURES, resolveProcedures } from "./procedures.js";

interface FakeFixtureService {
  name: string;
  kind: ServiceKind;
  enabled?: boolean;
  source?: ServiceSource;
  envDocument?: string;
  resources?: Resources;
  deploy?: DeploySettings;
  domains?: ServiceDomain[];
  healthcheck?: Healthcheck | null;
  status?: ServiceRuntimeStatus;
  health?: ServiceHealthStatus;
  readiness?: ServiceReadiness;
}

export interface FakeFixture {
  version: string;
  projects: Array<{ name: string; services: FakeFixtureService[] }>;
}

const FakeFixtureServiceSchema = z
  .object({
    name: ServiceNameSchema,
    kind: z.enum(["app", "postgres", "redis"]),
    enabled: z.boolean().optional(),
    source: SourceSchema.optional(),
    envDocument: z.string().max(262_144).refine((value) => !value.includes("\u0000")).optional(),
    resources: ResourcesSchema.optional(),
    deploy: DeploySettingsSchema.optional(),
    domains: z.array(DomainSchema).max(50).optional(),
    healthcheck: HealthcheckSchema.nullable().optional(),
    status: z.enum(["running", "stopped", "deploying", "error", "unknown"]).optional(),
    health: z.enum(["healthy", "unhealthy", "unknown"]).optional(),
    readiness: z.enum(["ready", "not_ready", "unknown"]).optional(),
  })
  .strict()
  .superRefine((service, context) => {
    if (
      service.readiness === "ready" &&
      (service.enabled === false ||
        service.status === "stopped" ||
        service.status === "error" ||
        service.health === "unhealthy")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readiness"],
        message: "A ready fixture must have a compatible runtime state",
      });
    }
    if (service.kind !== "app") {
      for (const field of [
        "source",
        "envDocument",
        "resources",
        "deploy",
        "domains",
        "healthcheck",
      ] as const) {
        if (service[field] !== undefined) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: [field],
            message: "Only app fixtures may contain app configuration",
          });
        }
      }
    }
  });

const FakeFixtureSchema = z
  .object({
    version: z.string().min(1).max(64).regex(/^[A-Za-z0-9.+-]+$/),
    projects: z
      .array(
        z
          .object({
            name: ProjectNameSchema,
            services: z.array(FakeFixtureServiceSchema).max(500),
          })
          .strict(),
      )
      .max(100),
  })
  .strict()
  .superRefine((fixture, context) => {
    const projects = new Set<string>();
    for (const [projectIndex, project] of fixture.projects.entries()) {
      if (projects.has(project.name)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["projects", projectIndex, "name"],
          message: "Duplicate project",
        });
      }
      projects.add(project.name);
      const services = new Set<string>();
      for (const [serviceIndex, service] of project.services.entries()) {
        if (services.has(service.name)) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["projects", projectIndex, "services", serviceIndex, "name"],
            message: "Duplicate service",
          });
        }
        services.add(service.name);
      }
    }
  });

export interface FakeMutation {
  type: string;
  project: string;
  service?: string;
  auditId: string;
}

export class FakeEasypanelGateway implements EasypanelGateway {
  readonly #projects = new Map<string, Map<string, InternalServiceSnapshot>>();
  readonly #deployments = new Map<string, DeploymentSummary & { requestId: string }>();
  readonly #version: string;
  readonly #secrets: SecretRegistry;
  readonly #webhookTokens = new Map<string, string>();
  readonly #lifecycleActions = new Map<
    string,
    {
      project: string;
      service: string;
      operation: LifecycleOperation;
      status: LifecycleActionStatus;
      requestId: string;
    }
  >();
  readonly mutations: FakeMutation[] = [];
  #sequence = 0;

  constructor(fixture: FakeFixture, secrets = new SecretRegistry()) {
    const validated = FakeFixtureSchema.safeParse(fixture);
    if (!validated.success) throw codedError("INVALID_FIXTURE", "Invalid fake fixture");
    fixture = validated.data as FakeFixture;
    this.#version = fixture.version;
    this.#secrets = secrets;

    for (const project of fixture.projects) {
      const services = new Map<string, InternalServiceSnapshot>();
      for (const service of project.services) {
        const enabled = service.enabled ?? true;
        const status = service.status ?? "running";
        services.set(service.name, {
          exists: true,
          project: project.name,
          service: service.name,
          kind: service.kind,
          enabled,
          source: service.source,
          envDocument: service.envDocument ?? "",
          resources: service.resources,
          deploy: service.deploy,
          domains: structuredClone(service.domains ?? []),
          healthcheck: service.healthcheck,
          status,
          health:
            service.health ??
            (status === "running" ? "healthy" : status === "error" ? "unhealthy" : "unknown"),
          readiness:
            service.readiness ??
            (enabled && status === "running"
              ? "ready"
              : !enabled || status === "stopped" || status === "error"
                ? "not_ready"
                : "unknown"),
        });
        validateFakeEnvironment(service.envDocument ?? "", "INVALID_FIXTURE");
      }
      this.#projects.set(project.name, services);
    }
  }

  static async fromFile(path: string, secrets?: SecretRegistry): Promise<FakeEasypanelGateway> {
    let text: string;
    try {
      const handle = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        const metadata = await handle.stat();
        if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size > 1_048_576) {
          throw codedError("INVALID_FIXTURE", "Invalid fake fixture");
        }
        text = await handle.readFile("utf8");
      } finally {
        await handle.close();
      }
    } catch (error: unknown) {
      if (hasCode(error, "INVALID_FIXTURE")) throw error;
      throw codedError("INVALID_FIXTURE", "Invalid fake fixture");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw codedError("INVALID_FIXTURE", "Invalid fake fixture");
    }
    return new FakeEasypanelGateway(parsed as FakeFixture, secrets);
  }

  async discover(): Promise<CapabilitySnapshot> {
    const available = new Map<string, ProcedureType>();
    for (const definition of Object.values(PROCEDURES)) {
      available.set(definition.candidates[0] as string, definition.type);
    }
    const resolved = resolveProcedures(available, true);
    return {
      instanceId: sha256("fake-easypanel").slice(0, 16),
      instanceLabel: "offline-fixture",
      flavor: "fake",
      version: this.#version,
      profile: "fake-complete",
      procedures: resolved.byName,
      features: resolved.features,
    };
  }

  async refreshCapabilities(): Promise<CapabilitySnapshot> {
    return this.discover();
  }

  async listInventory(): Promise<Inventory> {
    return {
      projects: [...this.#projects.keys()].sort().map((name) => ({ name })),
      services: [...this.#projects.entries()]
        .flatMap(([project, services]) =>
          [...services.values()].map((service) => ({
            project,
            name: service.service,
            kind: service.kind,
            enabled: service.enabled,
          })),
        )
        .sort((left, right) =>
          compareCodePoints(
            `${left.project}/${left.name}`,
            `${right.project}/${right.name}`,
          ),
        ),
    };
  }

  async inspectService(
    project: string,
    service: string,
    expectedKind?: ServiceKind,
  ): Promise<InternalServiceSnapshot> {
    const found = this.#projects.get(project)?.get(service);
    if (!found) {
      return {
        exists: false,
        project,
        service,
        kind: expectedKind ?? "app",
        enabled: false,
        envDocument: "",
      };
    }
    if (expectedKind && found.kind !== expectedKind) {
      throw codedError("SERVICE_KIND_MISMATCH", "The service kind does not match the plan");
    }
    registerFakeEnvironment(found.envDocument, this.#secrets, "INVALID_FIXTURE");
    return structuredClone(found);
  }

  async listDeployments(project: string, service: string): Promise<DeploymentSummary[]> {
    return [...this.#deployments.values()]
      .filter((entry) => entry.project === project && entry.service === service)
      .sort((left, right) => compareCodePoints(right.createdAt!, left.createdAt!))
      .map((summary) => publicDeployment(summary));
  }

  async getDeployment(id: string): Promise<DeploymentSummary | null> {
    const found = this.#deployments.get(id);
    if (!found) return null;
    return publicDeployment(found);
  }

  async getDeploymentForRequest(
    id: string,
    project: string,
    service: string,
    requestId: string,
  ): Promise<DeploymentSummary | null> {
    const found = this.#deployments.get(id);
    if (!found) return null;
    if (
      found.project !== project ||
      found.service !== service ||
      found.requestId !== requestId
    ) {
      throw codedError("UPSTREAM_TARGET_MISMATCH", "Fixture deployment target does not match");
    }
    return publicDeployment(found);
  }

  async listLifecycleActions(
    project: string,
    service: string,
  ): Promise<LifecycleActionSummary[]> {
    return [...this.#lifecycleActions.entries()]
      .filter(([, action]) => action.project === project && action.service === service)
      .map(([id, action]) => ({
        id,
        project: action.project,
        service: action.service,
        operation: action.operation,
        status: action.status,
      }))
      .sort((left, right) => compareCodePoints(left.id, right.id));
  }

  async getLifecycleActionStatus(
    id: string,
    project: string,
    service: string,
    operation: LifecycleOperation,
    requestId: string,
  ): Promise<LifecycleActionStatus | null> {
    const action = this.#lifecycleActions.get(id);
    if (!action) return null;
    if (
      action.project !== project ||
      action.service !== service ||
      action.operation !== operation ||
      action.requestId !== requestId
    ) {
      throw codedError("UPSTREAM_TARGET_MISMATCH", "Fixture action target does not match");
    }
    return action.status;
  }

  async getDeployWebhookFingerprint(
    project: string,
    service: string,
  ): Promise<string | undefined> {
    this.#requireService(project, service);
    const key = `${project}/${service}`;
    const token = this.#webhookTokens.get(key) ?? "fixture-initial-webhook-token";
    this.#secrets.add(token);
    return sha256({ purpose: "webhook-fingerprint", token });
  }

  async createProject(project: string, context: GatewayMutationContext): Promise<void> {
    if (!this.#projects.has(project)) {
      this.#projects.set(project, new Map());
      this.#record("create_project", project, undefined, context);
    }
  }

  async createService(
    project: string,
    service: string,
    kind: ServiceKind,
    options: { password?: string },
    context: GatewayMutationContext,
  ): Promise<CreateServiceEvidence> {
    if (kind === "app" && options.password !== undefined) {
      throw codedError("INVALID_INPUT", "App services cannot receive a database password");
    }
    if (
      kind !== "app" &&
      (options.password === undefined || Buffer.byteLength(options.password, "utf8") < 8)
    ) {
      throw codedError("INVALID_INPUT", "Database services require a bootstrap credential");
    }
    if (options.password !== undefined) this.#secrets.add(options.password);
    const services = this.#requireProject(project);
    if (!services.has(service)) {
      services.set(service, {
        exists: true,
        project,
        service,
        kind,
        enabled: true,
        envDocument: "",
        domains: [],
        status: "unknown",
        health: "unknown",
        readiness: "unknown",
      });
      this.#record("create_service", project, service, context);
    }
    return kind === "app" ? {} : { databaseCredentialAccepted: true };
  }

  async updateSource(
    project: string,
    service: string,
    source: ServiceSource,
    context: GatewayMutationContext,
  ): Promise<void> {
    this.#requireService(project, service).source = structuredClone(source);
    this.#record("update_source", project, service, context);
  }

  async updateEnvironment(
    project: string,
    service: string,
    envDocument: string,
    context: GatewayMutationContext,
  ): Promise<void> {
    const target = this.#requireService(project, service);
    registerFakeEnvironment(envDocument, this.#secrets, "INVALID_INPUT");
    target.envDocument = envDocument;
    this.#record("update_environment", project, service, context);
  }

  async updateResources(
    project: string,
    service: string,
    resources: Resources,
    context: GatewayMutationContext,
  ): Promise<void> {
    this.#requireService(project, service).resources = structuredClone(resources);
    this.#record("update_resources", project, service, context);
  }

  async updateDeploy(
    project: string,
    service: string,
    deploy: DeploySettings,
    context: GatewayMutationContext,
  ): Promise<void> {
    this.#requireService(project, service).deploy = structuredClone(deploy);
    this.#record("update_deploy", project, service, context);
  }

  async addDomain(
    project: string,
    service: string,
    domain: ServiceDomain,
    context: GatewayMutationContext,
  ): Promise<void> {
    const target = this.#requireService(project, service);
    target.domains ??= [];
    if (!target.domains.some((entry) => entry.host === domain.host)) {
      target.domains.push(structuredClone(domain));
      this.#record("add_domain", project, service, context);
    }
  }

  async removeDomain(
    project: string,
    service: string,
    host: string,
    context: GatewayMutationContext,
  ): Promise<void> {
    const target = this.#requireService(project, service);
    const before = target.domains?.length ?? 0;
    target.domains = (target.domains ?? []).filter((entry) => entry.host !== host);
    if (target.domains.length !== before) this.#record("remove_domain", project, service, context);
  }

  async updateHealthcheck(
    project: string,
    service: string,
    healthcheck: Healthcheck | null,
    context: GatewayMutationContext,
  ): Promise<void> {
    this.#requireService(project, service).healthcheck = structuredClone(healthcheck);
    this.#record("update_healthcheck", project, service, context);
  }

  async destroyService(
    project: string,
    service: string,
    _kind: ServiceKind,
    context: GatewayMutationContext,
  ): Promise<void> {
    if (this.#projects.get(project)?.delete(service)) {
      this.#record("destroy_service", project, service, context);
    }
  }

  async deployService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    const target = this.#requireService(project, service);
    if (target.kind !== "app") throw codedError("UNSUPPORTED_SERVICE_KIND", "Only apps deploy");
    const id = `fake-action-${++this.#sequence}`;
    const now = new Date(Date.UTC(2026, 6, 11, 12, 0, this.#sequence)).toISOString();
    this.#deployments.set(id, {
      id,
      project,
      service,
      status: "running",
      createdAt: now,
      finishedAt: now,
      requestId: context.auditId,
    });
    target.status = "running";
    target.health = "healthy";
    target.readiness = "ready";
    this.#record("deploy_service", project, service, context);
    return id;
  }

  async startService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    const target = this.#requireApp(project, service);
    target.enabled = true;
    target.status = "running";
    target.health = "healthy";
    target.readiness = "ready";
    this.#record("start_service", project, service, context);
    return this.#recordLifecycleAction(project, service, "start", context.auditId);
  }

  async stopService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    const target = this.#requireApp(project, service);
    target.enabled = false;
    target.status = "stopped";
    target.health = "unknown";
    target.readiness = "not_ready";
    this.#record("stop_service", project, service, context);
    return this.#recordLifecycleAction(project, service, "stop", context.auditId);
  }

  async restartService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    const target = this.#requireApp(project, service);
    target.enabled = true;
    target.status = "running";
    target.health = "healthy";
    target.readiness = "ready";
    this.#record("restart_service", project, service, context);
    return this.#recordLifecycleAction(project, service, "restart", context.auditId);
  }

  async rotateDeployWebhook(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    this.#requireService(project, service);
    const fakeToken = `fixture-only-token-${++this.#sequence}`;
    this.#secrets.add(fakeToken);
    this.#webhookTokens.set(`${project}/${service}`, fakeToken);
    this.#record("rotate_deploy_webhook", project, service, context);
    return fakeToken;
  }

  #requireProject(project: string): Map<string, InternalServiceSnapshot> {
    const found = this.#projects.get(project);
    if (!found) throw codedError("PROJECT_NOT_FOUND", "Fixture project does not exist");
    return found;
  }

  #recordLifecycleAction(
    project: string,
    service: string,
    operation: LifecycleOperation,
    requestId: string,
  ): string {
    if (this.#lifecycleActions.size >= 50) {
      throw codedError(
        "LIFECYCLE_HISTORY_CAPACITY",
        "Fixture lifecycle history cannot remain complete",
      );
    }
    const id = `fake-lifecycle-${++this.#sequence}`;
    this.#lifecycleActions.set(id, {
      project,
      service,
      operation,
      status: "succeeded",
      requestId,
    });
    return id;
  }

  #requireService(project: string, service: string): InternalServiceSnapshot {
    const found = this.#projects.get(project)?.get(service);
    if (!found) throw codedError("SERVICE_NOT_FOUND", "Fixture service does not exist");
    return found;
  }

  #requireApp(project: string, service: string): InternalServiceSnapshot {
    const found = this.#requireService(project, service);
    if (found.kind !== "app") throw codedError("UNSUPPORTED_SERVICE_KIND", "Only apps support lifecycle operations");
    return found;
  }

  #record(
    type: string,
    project: string,
    service: string | undefined,
    context: GatewayMutationContext,
  ): void {
    this.mutations.push({ type, project, service, auditId: context.auditId });
  }
}

function validateFakeEnvironment(
  document: string,
  errorCode: "INVALID_FIXTURE" | "INVALID_INPUT",
): Array<{ name: string; value: string }> {
  let entries: Array<{ name: string; value: string }>;
  try {
    entries = EnvDocument.parse(document).entries();
  } catch {
    throw codedError(errorCode, "Invalid fake environment document");
  }
  for (const { name, value } of entries) {
    if (isSensitiveEnvName(name) && Buffer.byteLength(value, "utf8") < 8) {
      throw codedError(errorCode, "Sensitive fake environment values are too short");
    }
  }
  return entries;
}

function registerFakeEnvironment(
  document: string,
  secrets: SecretRegistry,
  errorCode: "INVALID_FIXTURE" | "INVALID_INPUT",
): void {
  for (const { value } of validateFakeEnvironment(document, errorCode)) {
    secrets.add(value);
  }
}

function codedError(code: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, "code", { value: code });
  return error;
}

function publicDeployment(
  deployment: DeploymentSummary & { requestId: string },
): DeploymentSummary {
  return {
    id: deployment.id,
    project: deployment.project,
    service: deployment.service,
    status: deployment.status,
    ...(deployment.createdAt ? { createdAt: deployment.createdAt } : {}),
    ...(deployment.finishedAt ? { finishedAt: deployment.finishedAt } : {}),
  };
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
