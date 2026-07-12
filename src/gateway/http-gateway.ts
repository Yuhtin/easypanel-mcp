import { randomBytes } from "node:crypto";

import { compareCodePoints, sha256 } from "../core/canonical-json.js";
import { currentInvocationAbort } from "../core/invocation-abort.js";
import {
  isSensitiveKey,
  isSensitiveEnvName,
  SecretRegistry,
} from "../core/redaction.js";
import { EnvDocument } from "../domain/env-document.js";
import {
  DeploySettingsSchema,
  DomainSchema,
  HealthcheckSchema,
  ResourcesSchema,
  SourceSchema,
  type DeploySettings,
  type Healthcheck,
  type Resources,
  type ServiceDomain,
  type ServiceSource,
} from "../domain/schemas.js";
import type {
  ApiFlavor,
  CapabilitySnapshot,
  DeploymentSummary,
  GatewayMutationContext,
  InternalServiceSnapshot,
  Inventory,
  LifecycleActionSummary,
  LifecycleActionStatus,
  LifecycleOperation,
  ProcedureType,
  ServiceKind,
} from "../domain/types.js";
import type { CreateServiceEvidence, EasypanelGateway } from "./gateway.js";
import {
  legacy230ProcedureMap,
  PROCEDURES,
  type ProcedureKey,
  resolveProcedures,
  type ResolvedProcedures,
} from "./procedures.js";

const IDENTIFIER_PATTERN = /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/;
const OPAQUE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_VERSION_PATTERN = /^\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]{1,64})?$/;
const MAX_PROJECTS = 1_000;
const MAX_SERVICES = 10_000;
const MAX_DOMAINS = 200;
const MAX_DEPLOYMENTS = 50;
const MAX_LIFECYCLE_ACTIONS = 50;
const MAX_OPENAPI_PATHS = 2_000;
// The largest contract-valid inventory needs ~52k visits before normalization
// (1k projects + 10k services and their required scalar fields). Keep a bounded
// margin for envelope fields without weakening the independent 10 MiB body cap.
const MAX_SENSITIVE_SCAN_NODES = 100_000;
const MAX_SENSITIVE_SCAN_DEPTH = 64;
const MAX_SECRETS_PER_RESPONSE = 512;
const MAX_SECRET_BYTES_PER_RESPONSE = 262_144;
const MAX_RESPONSE_CHUNKS = 4_096;
const MAX_SENSITIVE_CONTAINER_ENTRIES = 10_000;

export interface HttpGatewayOptions {
  baseUrl: URL;
  token: string;
  instanceLabel: string;
  apiFlavor: "auto" | "rpc" | "trpc";
  expectedVersion: string;
  timeoutMs: number;
  maxResponseBytes: number;
  secrets: SecretRegistry;
  fetch?: typeof globalThis.fetch;
}

export class GatewayError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "GatewayError";
    this.code = code;
    this.status = status;
  }
}

interface DiscoveryState {
  public: CapabilitySnapshot;
  procedures: ResolvedProcedures;
}

interface MutationExpectation {
  project?: string;
  service?: string;
  kind?: ServiceKind;
  requestId?: string;
}

type NormalizedStatus = "running" | "stopped" | "deploying" | "error" | "unknown";

export class HttpEasypanelGateway implements EasypanelGateway {
  readonly #baseUrl: URL;
  readonly #token: string;
  readonly #instanceLabel: string;
  readonly #apiFlavor: HttpGatewayOptions["apiFlavor"];
  readonly #expectedVersion: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #secrets: SecretRegistry;
  readonly #fetch: typeof globalThis.fetch;
  #discovery?: Promise<DiscoveryState>;

  constructor(options: HttpGatewayOptions) {
    assertSafeOrigin(options.baseUrl);
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
      throw new GatewayError(
        "TLS_VALIDATION_DISABLED",
        "TLS certificate validation must remain enabled",
      );
    }
    if (
      options.token.length < 16 ||
      options.token.length > 8_192 ||
      /\s|[\u0000-\u001f\u007f]/.test(options.token)
    ) {
      throw new GatewayError("INVALID_CONFIGURATION", "Easypanel token is missing or too short");
    }
    if (!IDENTIFIER_PATTERN.test(options.instanceLabel)) {
      throw new GatewayError("INVALID_CONFIGURATION", "Easypanel instance label is invalid");
    }
    if (
      !Number.isSafeInteger(options.timeoutMs) ||
      options.timeoutMs < 1_000 ||
      options.timeoutMs > 60_000 ||
      !Number.isSafeInteger(options.maxResponseBytes) ||
      options.maxResponseBytes < 1_024 ||
      options.maxResponseBytes > 10_485_760
    ) {
      throw new GatewayError("INVALID_CONFIGURATION", "HTTP safety limits are invalid");
    }
    if (!SAFE_VERSION_PATTERN.test(options.expectedVersion)) {
      throw new GatewayError("INVALID_CONFIGURATION", "Expected Easypanel version is invalid");
    }

    this.#baseUrl = new URL(options.baseUrl.origin);
    this.#token = options.token;
    this.#instanceLabel = options.instanceLabel;
    this.#apiFlavor = options.apiFlavor;
    this.#expectedVersion = options.expectedVersion;
    this.#timeoutMs = options.timeoutMs;
    this.#maxResponseBytes = options.maxResponseBytes;
    this.#secrets = options.secrets;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#secrets.add(options.token);
  }

  async discover(): Promise<CapabilitySnapshot> {
    return (await this.#getDiscovery()).public;
  }

  async refreshCapabilities(): Promise<CapabilitySnapshot> {
    this.#discovery = undefined;
    return this.discover();
  }

  async listInventory(): Promise<Inventory> {
    return normalizeInventory(await this.#call("inventory", {}));
  }

  async inspectService(
    project: string,
    service: string,
    expectedKind?: ServiceKind,
  ): Promise<InternalServiceSnapshot> {
    const rawInventory = await this.#call("inventory", {});
    const inventory = normalizeInventory(rawInventory);
    const summary = inventory.services.find(
      (entry) => entry.project === project && entry.name === service,
    );
    const actualKind = toSupportedKind(summary?.kind);
    const kind = actualKind ?? expectedKind;

    if (!summary) {
      await this.#confirmServiceAbsent(
        project,
        service,
        inventory.projects.some((entry) => entry.name === project),
      );
      return {
        exists: false,
        project,
        service,
        kind: kind ?? "app",
        enabled: false,
        envDocument: "",
      };
    }
    if (!actualKind || !kind) {
      throw new GatewayError(
        "UNSUPPORTED_SERVICE_KIND",
        "The service type is not supported by this MCP",
      );
    }
    if (expectedKind && actualKind !== expectedKind) {
      throw new GatewayError("SERVICE_KIND_MISMATCH", "The service kind does not match the plan");
    }

    const raw = requireServiceRecord(
      await this.#call(inspectKey(kind), { projectName: project, serviceName: service }),
      project,
      service,
      kind,
    );
    const inventoryService = findInventoryServiceRecord(rawInventory, project, service);
    crossCheckServiceConfiguration(inventoryService, raw);
    const envDocument = kind === "app" ? requireStringField(raw, "env", 1_048_576, true) : "";
    registerEnvValues(envDocument, this.#secrets);

    let domains: ServiceDomain[] | undefined;
    if (kind === "app") {
      domains = normalizeDomains(
        await this.#call("list_domains", { projectName: project, serviceName: service }),
        project,
        service,
      );
    }
    const enabled = requireBooleanField(raw, "enabled");
    const status = normalizeOptionalStatus(raw, ["status", "state"]);
    const health = normalizeOptionalHealth(raw);
    const readiness = normalizeOptionalReadiness(raw);
    if (
      readiness === "ready" &&
      (!enabled || status === "stopped" || status === "error" || health === "unhealthy")
    ) {
      invalidUpstream();
    }

    return {
      exists: true,
      project,
      service,
      kind,
      enabled,
      source: kind === "app" ? normalizeOptionalSource(raw.source) : undefined,
      envDocument,
      resources: kind === "app" ? normalizeOptionalResources(raw.resources) : undefined,
      deploy: kind === "app" ? normalizeOptionalDeploy(raw.deploy) : undefined,
      domains,
      healthcheck: kind === "app" ? normalizeOptionalHealthcheck(raw.healthcheck) : undefined,
      status,
      health,
      readiness,
    };
  }

  async listDeployments(project: string, service: string): Promise<DeploymentSummary[]> {
    const raw = await this.#call("list_actions", {
      projectName: project,
      serviceName: service,
      type: "deployment",
      limit: 50,
    });
    const entries = requireArray(raw, MAX_DEPLOYMENTS);
    const deployments = entries.map((entry) =>
      normalizeDeployment(entry, { project, service, expectedType: "deployment" }),
    );
    if (new Set(deployments.map(({ id }) => id)).size !== deployments.length) {
      invalidUpstream();
    }
    return deployments.sort((left, right) =>
      compareCodePoints(right.createdAt, left.createdAt),
    );
  }

  async getDeployment(id: string): Promise<DeploymentSummary | null> {
    if (!OPAQUE_ID_PATTERN.test(id)) {
      throw new GatewayError("INVALID_INPUT", "Invalid deployment identifier");
    }
    return normalizeDeployment(await this.#call("get_action", { id }), {
      expectedId: id,
      expectedType: "deployment",
    });
  }

  async getDeploymentForRequest(
    id: string,
    project: string,
    service: string,
    requestId: string,
  ): Promise<DeploymentSummary | null> {
    if (!OPAQUE_ID_PATTERN.test(id) || !OPAQUE_ID_PATTERN.test(requestId)) {
      throw new GatewayError("INVALID_INPUT", "Invalid deployment correlation identifier");
    }
    const value = requireRecord(await this.#call("get_action", { id }));
    if (requireOpaqueIdField(value, "clientRequestId") !== requestId) targetMismatch();
    return normalizeDeployment(value, {
      expectedId: id,
      project,
      service,
      expectedType: "deployment",
    });
  }

  async listLifecycleActions(
    project: string,
    service: string,
  ): Promise<LifecycleActionSummary[]> {
    const raw = await this.#call("list_actions", {
      projectName: project,
      serviceName: service,
      type: "lifecycle",
      limit: MAX_LIFECYCLE_ACTIONS + 1,
    });
    const page = requireRecord(raw);
    const entries = requireArrayField(page, "items", MAX_LIFECYCLE_ACTIONS + 1);
    const total = requireSafeIntegerField(page, "total", 0, MAX_LIFECYCLE_ACTIONS + 1);
    if (
      requireBooleanField(page, "hasMore") ||
      total !== entries.length ||
      entries.length > MAX_LIFECYCLE_ACTIONS
    ) {
      invalidUpstream();
    }
    const actions = entries.map((entry) => {
      const value = requireRecord(entry);
      if (requireSafeEnumLikeField(value, "type", 32) !== "lifecycle") {
        targetMismatch();
      }
      const id = requireOpaqueIdField(value, "id");
      assertTargetOwnership(value, project, service);
      return {
        id,
        project,
        service,
        operation: requireLifecycleOperation(value),
        status: requireLifecycleActionStatusField(value, "status"),
      };
    });
    if (new Set(actions.map(({ id }) => id)).size !== actions.length) {
      invalidUpstream();
    }
    return actions.sort((left, right) => compareCodePoints(left.id, right.id));
  }

  async getLifecycleActionStatus(
    id: string,
    project: string,
    service: string,
    operation: LifecycleOperation,
    requestId: string,
  ): Promise<LifecycleActionStatus | null> {
    if (!OPAQUE_ID_PATTERN.test(id)) {
      throw new GatewayError("INVALID_INPUT", "Invalid lifecycle action identifier");
    }
    const value = requireRecord(await this.#call("get_action", { id }));
    if (requireOpaqueIdField(value, "id") !== id) targetMismatch();
    if (requireSafeEnumLikeField(value, "type", 32) !== "lifecycle") targetMismatch();
    assertTargetOwnership(value, project, service);
    if (requireLifecycleOperation(value) !== operation) targetMismatch();
    if (requireOpaqueIdField(value, "clientRequestId") !== requestId) targetMismatch();
    return requireLifecycleActionStatusField(value, "status");
  }

  async getDeployWebhookFingerprint(
    project: string,
    service: string,
  ): Promise<string | undefined> {
    const raw = requireServiceRecord(
      await this.#call("inspect_app", { projectName: project, serviceName: service }),
      project,
      service,
      "app",
    );
    const tokenKeys = ["token", "deployToken", "deployWebhook", "webhookToken"].filter(
      (key) => Object.hasOwn(raw, key),
    );
    if (tokenKeys.length === 0) return undefined;
    const token = extractWebhookToken(raw);
    this.#secrets.add(token);
    return sha256({ purpose: "webhook-fingerprint", token });
  }

  async createProject(project: string, _context: GatewayMutationContext): Promise<void> {
    await this.#mutate("create_project", { name: project }, { project });
  }

  async createService(
    project: string,
    service: string,
    kind: ServiceKind,
    options: { password?: string },
    _context: GatewayMutationContext,
  ): Promise<CreateServiceEvidence> {
    if (kind === "app" && options.password !== undefined) {
      throw new GatewayError("INVALID_INPUT", "App services cannot receive a database password");
    }
    if (kind !== "app" && options.password === undefined) {
      throw new GatewayError(
        "INVALID_INPUT",
        "Database services require an explicit bootstrap credential",
      );
    }
    if (
      options.password !== undefined &&
      (Buffer.byteLength(options.password, "utf8") < 8 ||
        Buffer.byteLength(options.password, "utf8") > 4_096 ||
        /[\u0000\r\n]/.test(options.password))
    ) {
      throw new GatewayError("INVALID_INPUT", "Database password is invalid");
    }
    if (options.password !== undefined) this.#secrets.add(options.password);

    const result = await this.#mutate(
      createKey(kind),
      {
        projectName: project,
        serviceName: service,
        ...(kind !== "app" && options.password !== undefined
          ? { password: options.password }
          : {}),
      },
      { project, service, kind },
    );
    if (kind === "app") return {};
    const acknowledgement = requireRecord(result);
    if (acknowledgement.passwordConfigured !== true) {
      invalidUpstream();
    }
    return { databaseCredentialAccepted: true };
  }

  async updateSource(
    project: string,
    service: string,
    source: ServiceSource,
    _context: GatewayMutationContext,
  ): Promise<void> {
    if (source.type === "image") {
      await this.#mutate(
        "source_image",
        {
          projectName: project,
          serviceName: service,
          image: source.image,
        },
        { project, service, kind: "app" },
      );
      return;
    }
    const [owner, repository] = source.repository.split("/", 2);
    await this.#mutate(
      "source_git",
      {
        projectName: project,
        serviceName: service,
        owner,
        repo: repository,
        ref: source.ref,
        path: source.path,
      },
      { project, service, kind: "app" },
    );
  }

  async updateEnvironment(
    project: string,
    service: string,
    envDocument: string,
    _context: GatewayMutationContext,
  ): Promise<void> {
    registerEnvValues(envDocument, this.#secrets);
    await this.#mutate(
      "update_env",
      { projectName: project, serviceName: service, env: envDocument },
      { project, service, kind: "app" },
    );
  }

  async updateResources(
    project: string,
    service: string,
    resources: Resources,
    _context: GatewayMutationContext,
  ): Promise<void> {
    await this.#mutate(
      "update_resources",
      {
        projectName: project,
        serviceName: service,
        resources: {
          memoryReservation: resources.memoryReservationMb,
          memoryLimit: resources.memoryLimitMb,
          cpuReservation: resources.cpuReservation,
          cpuLimit: resources.cpuLimit,
        },
      },
      { project, service, kind: "app" },
    );
  }

  async updateDeploy(
    project: string,
    service: string,
    deploy: DeploySettings,
    _context: GatewayMutationContext,
  ): Promise<void> {
    await this.#mutate(
      "update_deploy",
      {
        projectName: project,
        serviceName: service,
        deploy: {
          replicas: deploy.replicas,
          zeroDowntime: deploy.zeroDowntime,
        },
      },
      { project, service, kind: "app" },
    );
  }

  async addDomain(
    project: string,
    service: string,
    domain: ServiceDomain,
    _context: GatewayMutationContext,
  ): Promise<void> {
    await this.#mutate(
      "create_domain",
      {
        id: `cm${randomBytes(13).toString("hex").slice(0, 22)}`,
        https: domain.https,
        host: domain.host,
        path: "/",
        middlewares: [],
        certificateResolver: "",
        wildcard: false,
        destinationType: "service",
        serviceDestination: {
          protocol: "http",
          port: domain.port,
          path: "/",
          projectName: project,
          serviceName: service,
          composeService: "",
        },
      },
      { project, service, kind: "app" },
    );
  }

  async removeDomain(
    project: string,
    service: string,
    host: string,
    _context: GatewayMutationContext,
  ): Promise<void> {
    const raw = await this.#call("list_domains", { projectName: project, serviceName: service });
    const records = normalizeDomainRecords(raw, project, service);
    const matches = records.filter((entry) => entry.domain.host === host);
    if (matches.length > 1) {
      throw new GatewayError("INVALID_UPSTREAM_RESPONSE", "Easypanel returned ambiguous domain ownership");
    }
    const match = matches[0];
    if (!match) return;
    await this.#mutate("delete_domain", { id: match.id }, { project, service, kind: "app" });
  }

  async updateHealthcheck(
    project: string,
    service: string,
    healthcheck: Healthcheck | null,
    _context: GatewayMutationContext,
  ): Promise<void> {
    await this.#mutate(
      "update_healthcheck",
      {
        projectName: project,
        serviceName: service,
        healthcheck,
      },
      { project, service, kind: "app" },
    );
  }

  async destroyService(
    project: string,
    service: string,
    kind: ServiceKind,
    _context: GatewayMutationContext,
  ): Promise<void> {
    await this.#mutate(
      destroyKey(kind),
      { projectName: project, serviceName: service },
      { project, service, kind },
    );
  }

  async deployService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    if (!OPAQUE_ID_PATTERN.test(context.auditId)) {
      throw new GatewayError("INVALID_INPUT", "Invalid deployment request identifier");
    }
    const result = await this.#mutate(
      "deploy_app",
      {
        projectName: project,
        serviceName: service,
        clientRequestId: context.auditId,
      },
      { project, service, requestId: context.auditId },
    );
    const record = requireRecord(result);
    if (requireSafeEnumLikeField(record, "type", 32) !== "deployment") targetMismatch();
    return requireMutationId(record);
  }

  async startService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    return this.#changeLifecycle("start_app", "start", project, service, context);
  }

  async stopService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    return this.#changeLifecycle("stop_app", "stop", project, service, context);
  }

  async restartService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    return this.#changeLifecycle("restart_app", "restart", project, service, context);
  }

  async rotateDeployWebhook(
    project: string,
    service: string,
    _context: GatewayMutationContext,
  ): Promise<string> {
    const result = await this.#call(
      "rotate_deploy_webhook",
      {
        projectName: project,
        serviceName: service,
      },
    );
    const record = requireRecord(result);
    assertMutationAcknowledgement(record, { project, service });
    const token = extractWebhookToken(record);
    registerSensitiveFields(result, this.#secrets);
    this.#secrets.add(token);
    return token;
  }

  async #mutate(
    key: ProcedureKey,
    input: Record<string, unknown>,
    expectation: MutationExpectation,
  ): Promise<unknown> {
    const result = await this.#call(key, input);
    assertMutationAcknowledgement(result, expectation);
    return result;
  }

  async #changeLifecycle(
    key: "start_app" | "stop_app" | "restart_app",
    operation: LifecycleOperation,
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string> {
    if (!OPAQUE_ID_PATTERN.test(context.auditId)) {
      throw new GatewayError("INVALID_INPUT", "Invalid lifecycle request identifier");
    }
    const result = await this.#mutate(
      key,
      {
        projectName: project,
        serviceName: service,
        clientRequestId: context.auditId,
      },
      { project, service, requestId: context.auditId },
    );
    const value = requireRecord(result);
    if (requireSafeEnumLikeField(value, "type", 32) !== "lifecycle") targetMismatch();
    if (requireLifecycleOperation(value) !== operation) targetMismatch();
    return requireMutationId(value);
  }

  async #confirmServiceAbsent(
    project: string,
    service: string,
    projectExistsInInventory: boolean,
  ): Promise<void> {
    try {
      const raw = requireRecord(
        await this.#call("inspect_project", { projectName: project }),
      );
      const inspectedProject = requireRecordField(raw, "project");
      if (requireIdentifierField(inspectedProject, "name") !== project) targetMismatch();
      if (!projectExistsInInventory) {
        throw new GatewayError(
          "INVENTORY_INCONSISTENT",
          "Easypanel inventory is inconsistent with project inspection",
        );
      }
      const services = requireArrayField(raw, "services", MAX_SERVICES);
      const names = new Set<string>();
      for (const rawService of services) {
        const entry = requireRecord(rawService);
        if (requireIdentifierField(entry, "projectName") !== project) targetMismatch();
        const name = requireServiceNameField(entry);
        requireSafeEnumLikeField(entry, "type", 32);
        requireBooleanField(entry, "enabled");
        if (names.has(name)) invalidUpstream();
        names.add(name);
      }
      if (names.has(service)) {
        throw new GatewayError(
          "INVENTORY_INCONSISTENT",
          "Easypanel inventory is inconsistent with project inspection",
        );
      }
    } catch (error: unknown) {
      if (error instanceof GatewayError && error.status === 404) {
        if (projectExistsInInventory) {
          throw new GatewayError(
            "INVENTORY_INCONSISTENT",
            "Easypanel inventory is inconsistent with project inspection",
          );
        }
        return;
      }
      throw error;
    }
  }

  async #getDiscovery(): Promise<DiscoveryState> {
    this.#discovery ??= this.#discoverInternal().catch((error: unknown) => {
      this.#discovery = undefined;
      throw error;
    });
    return this.#discovery;
  }

  async #discoverInternal(): Promise<DiscoveryState> {
    if (this.#apiFlavor !== "trpc") {
      const rpc = await this.#discoverRpc(this.#apiFlavor === "rpc");
      if (rpc) return rpc;
    }
    return this.#discoverLegacy();
  }

  async #discoverRpc(required: boolean): Promise<DiscoveryState | null> {
    const spec = await this.#withResponse<Record<string, unknown> | undefined>(
      "/api/openapi.json",
      { method: "GET" },
      true,
      [404],
      async (response, signal) => {
        if (response.status === 404) {
          cancelResponseBody(response);
          return undefined;
        }
        return requireRecord(await this.#readJson(response, signal));
      },
    );
    if (spec === undefined) {
      if (required) throw new GatewayError("INCOMPATIBLE_API", "RPC OpenAPI is unavailable");
      return null;
    }
    const available = exactAllowlistedProcedures(parseOpenApiProcedures(spec));
    const procedures = resolveProcedures(available, true);
    const statusBody = await this.#withResponse(
      "/api/rpc/update/getStatus",
      { method: "POST", body: JSON.stringify({ json: {} }) },
      true,
      [],
      (response, signal) => this.#readJson(response, signal),
    );
    if (hasErrorEnvelope(statusBody)) {
      throw new GatewayError("UPSTREAM_REJECTED", "Easypanel rejected version discovery");
    }
    const version = requireVersion(unwrapEnvelope(statusBody, "rpc"));
    this.#assertExpectedVersion(version);
    return this.#makeDiscovery("rpc", version, "rpc-openapi", procedures);
  }

  async #discoverLegacy(): Promise<DiscoveryState> {
    const body = await this.#withResponse(
      "/api/trpc/update.getStatus",
      { method: "GET" },
      true,
      [],
      (response, signal) => this.#readJson(response, signal),
    );
    if (hasErrorEnvelope(body)) {
      throw new GatewayError("UPSTREAM_REJECTED", "Easypanel rejected version discovery");
    }
    const detected = requireVersion(unwrapEnvelope(body, "trpc"));
    if (!/^2\.30(?:\.|$)/.test(detected)) {
      throw new GatewayError(
        "INCOMPATIBLE_VERSION",
        "Legacy mode is supported only for an explicitly identified Easypanel 2.30.x instance",
      );
    }
    this.#assertExpectedVersion(detected);
    const procedures = resolveProcedures(legacy230ProcedureMap(), true);
    return this.#makeDiscovery("trpc", detected, "legacy-2.30", procedures);
  }

  #makeDiscovery(
    flavor: ApiFlavor,
    version: string,
    profile: string,
    procedures: ResolvedProcedures,
  ): DiscoveryState {
    return {
      public: {
        instanceId: sha256(this.#baseUrl.origin).slice(0, 16),
        instanceLabel: this.#instanceLabel,
        flavor,
        version,
        profile,
        procedures: procedures.byName,
        features: procedures.features,
      },
      procedures,
    };
  }

  #assertExpectedVersion(version: string): void {
    if (this.#expectedVersion !== version) {
      throw new GatewayError("VERSION_MISMATCH", "The Easypanel version does not match configuration");
    }
  }

  async #call(key: ProcedureKey, input: Record<string, unknown>): Promise<unknown> {
    const discovery = await this.#getDiscovery();
    const procedure = discovery.procedures.byKey.get(key);
    if (!procedure) {
      throw new GatewayError("FEATURE_UNSUPPORTED", "This operation is not supported by the panel profile");
    }
    const type = discovery.procedures.byName.get(procedure);
    if (!type) throw new GatewayError("PROCEDURE_BLOCKED", "Procedure is not allowlisted");

    let path: string;
    let init: RequestInit;
    if (discovery.public.flavor === "rpc") {
      // OpenAPI GET/POST is used only as the query/mutation security
      // classification. Easypanel's modern RPC transport requires POST with a
      // JSON envelope even for procedures documented semantically as GET.
      path = `/api/rpc/${procedure.split(".").join("/")}`;
      init = { method: "POST", body: JSON.stringify({ json: input }) };
    } else if (type === "query") {
      const encoded = encodeURIComponent(JSON.stringify({ json: input }));
      path = `/api/trpc/${procedure}?input=${encoded}`;
      init = { method: "GET" };
    } else {
      path = `/api/trpc/${procedure}`;
      init = { method: "POST", body: JSON.stringify({ json: input }) };
    }

    const result = await this.#withResponse(
      path,
      init,
      type === "query",
      [],
      async (response, signal) => ({
        body: await this.#readJson(response, signal),
        status: response.status,
      }),
    );
    if (hasErrorEnvelope(result.body)) {
      throw new GatewayError(
        "UPSTREAM_REJECTED",
        "Easypanel rejected the operation",
        result.status,
      );
    }
    const unwrapped = unwrapEnvelope(result.body, discovery.public.flavor);
    registerSensitiveFields(unwrapped, this.#secrets);
    return unwrapped;
  }

  async #withResponse<T>(
    path: string,
    init: RequestInit,
    retryable: boolean,
    allowedStatuses: readonly number[],
    consume: (response: Response, signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const target = new URL(path, this.#baseUrl);
    if (target.origin !== this.#baseUrl.origin) {
      throw new GatewayError("ORIGIN_VIOLATION", "Cross-origin requests are forbidden");
    }
    const invocationSignal = currentInvocationAbort();
    if (invocationSignal?.aborted) {
      throw new GatewayError("UPSTREAM_TIMEOUT", "Easypanel request timed out");
    }
    const attempts = retryable ? 2 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (invocationSignal?.aborted) {
        throw new GatewayError("UPSTREAM_TIMEOUT", "Easypanel request timed out");
      }
      const controller = new AbortController();
      const abortFromInvocation = (): void => controller.abort();
      if (invocationSignal?.aborted) abortFromInvocation();
      else invocationSignal?.addEventListener("abort", abortFromInvocation, { once: true });
      // AbortSignal.timeout() uses an unref'ed timer in Node. Use a regular
      // timer and retain it through both headers and bounded body consumption.
      // A peer that sends headers then stalls the body must not hold an
      // admission slot forever.
      const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
      try {
        const pendingResponse = this.#fetch(target, {
          ...init,
          redirect: "error",
          headers: {
            authorization: `Bearer ${this.#token}`,
            accept: "application/json",
            "content-type": "application/json",
          },
          signal: controller.signal,
        }).then((response) => {
          if (controller.signal.aborted) cancelResponseBody(response);
          return response;
        });
        const response = await awaitWithAbort(pendingResponse, controller.signal);
        if (
          !response.ok &&
          !allowedStatuses.includes(response.status) &&
          !(retryable && attempt + 1 < attempts && response.status >= 500)
        ) {
          cancelResponseBody(response);
          throw new GatewayError(
            `UPSTREAM_HTTP_${response.status}`,
            "Easypanel request failed",
            response.status,
          );
        }
        if (!response.ok && !allowedStatuses.includes(response.status)) {
          cancelResponseBody(response);
          continue;
        }
        return await consume(response, controller.signal);
      } catch (error: unknown) {
        // A request-scoped deadline is final. Retrying after it fired could
        // outlive the MCP request that owns the redaction/admission scope.
        if (invocationSignal?.aborted) {
          throw new GatewayError("UPSTREAM_TIMEOUT", "Easypanel request timed out");
        }
        if (
          error instanceof GatewayError &&
          (error.code !== "UPSTREAM_TIMEOUT" || !retryable || attempt + 1 >= attempts)
        ) {
          throw error;
        }
        lastError = error;
        if (!retryable || attempt + 1 >= attempts) break;
      } finally {
        clearTimeout(timeout);
        invocationSignal?.removeEventListener("abort", abortFromInvocation);
      }
    }
    if (lastError instanceof GatewayError && lastError.code === "UPSTREAM_TIMEOUT") {
      throw lastError;
    }
    throw new GatewayError("UPSTREAM_UNAVAILABLE", "Easypanel is unavailable or timed out");
  }

  async #readJson(response: Response, signal: AbortSignal): Promise<unknown> {
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && !/^\d+$/.test(contentLength)) {
      cancelResponseBody(response);
      throw new GatewayError("INVALID_UPSTREAM_RESPONSE", "Easypanel returned an invalid length header");
    }
    const declaredLength = Number(contentLength ?? "0");
    if (!Number.isSafeInteger(declaredLength) || declaredLength > this.#maxResponseBytes) {
      cancelResponseBody(response);
      throw new GatewayError("RESPONSE_TOO_LARGE", "Easypanel response exceeds the safety limit");
    }
    const bytes = await readBoundedBody(response, this.#maxResponseBytes, signal);
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      throw new GatewayError("INVALID_UPSTREAM_RESPONSE", "Easypanel returned invalid JSON");
    }
  }
}

export function parseOpenApiProcedures(
  spec: Record<string, unknown>,
): ReadonlyMap<string, ProcedureType> {
  const output = new Map<string, ProcedureType>();
  const paths = requireRecordField(spec, "paths");
  let pathCount = 0;
  for (const path in paths) {
    if (!Object.hasOwn(paths, path)) continue;
    pathCount += 1;
    if (pathCount > MAX_OPENAPI_PATHS) invalidUpstream();
    const rawOperations = paths[path];
    if (!path.startsWith("/api/rpc/")) continue;
    if (
      path.length > 256 ||
      !/^\/api\/rpc\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(path)
    ) {
      invalidUpstream();
    }
    const operations = requireRecord(rawOperations);
    const hasGet = Object.hasOwn(operations, "get");
    const hasPost = Object.hasOwn(operations, "post");
    if (hasGet && hasPost) invalidUpstream();
    if (!hasGet && !hasPost) continue;
    requireRecord(operations[hasGet ? "get" : "post"]);
    const procedure = path.slice("/api/rpc/".length).split("/").join(".");
    if (output.has(procedure)) invalidUpstream();
    output.set(procedure, hasGet ? "query" : "mutation");
  }
  return output;
}

export function normalizeInventory(raw: unknown): Inventory {
  const record = requireRecord(raw);
  const projectEntries = requireArrayField(record, "projects", MAX_PROJECTS);
  const serviceEntries = requireArrayField(record, "services", MAX_SERVICES);
  const projectNames = new Set<string>();
  const serviceTargets = new Set<string>();
  const projects = projectEntries.map((rawProject) => {
    const entry = requireRecord(rawProject);
    const name = requireIdentifierField(entry, "name");
    if (projectNames.has(name)) invalidUpstream();
    projectNames.add(name);
    return { name };
  });
  const services = serviceEntries.map((rawService) => {
    const entry = requireRecord(rawService);
    const project = requireIdentifierField(entry, "projectName");
    const name = requireIdentifierField(entry, "name");
    const kind = requireSafeEnumLikeField(entry, "type", 32);
    const enabled = requireBooleanField(entry, "enabled");
    if (!projectNames.has(project)) invalidUpstream();
    const target = `${project}\u0000${name}`;
    if (serviceTargets.has(target)) invalidUpstream();
    serviceTargets.add(target);
    return { project, name, kind, enabled };
  });
  return { projects, services };
}

function findInventoryServiceRecord(
  raw: unknown,
  project: string,
  service: string,
): Record<string, unknown> {
  const inventory = requireRecord(raw);
  const matches = requireArrayField(inventory, "services", MAX_SERVICES)
    .map(requireRecord)
    .filter(
      (entry) =>
        requireIdentifierField(entry, "projectName") === project &&
        requireServiceNameField(entry) === service,
    );
  if (matches.length !== 1) invalidUpstream();
  return matches[0] as Record<string, unknown>;
}

function crossCheckServiceConfiguration(
  inventory: Record<string, unknown>,
  inspection: Record<string, unknown>,
): void {
  for (const key of [
    "enabled",
    "env",
    "source",
    "resources",
    "deploy",
    "healthcheck",
  ] as const) {
    const inventoryHas = Object.hasOwn(inventory, key);
    const inspectionHas = Object.hasOwn(inspection, key);
    if (inventoryHas && (!inspectionHas || sha256(inventory[key]) !== sha256(inspection[key]))) {
      throw new GatewayError(
        "INVENTORY_INCONSISTENT",
        "Easypanel returned inconsistent service configuration",
      );
    }
  }
}

function exactAllowlistedProcedures(
  available: ReadonlyMap<string, ProcedureType>,
): ReadonlyMap<string, ProcedureType> {
  const exact = new Map<string, ProcedureType>();
  const allowed = new Map<string, ProcedureType>();
  for (const definition of Object.values(PROCEDURES)) {
    for (const candidate of definition.candidates) allowed.set(candidate, definition.type);
  }
  for (const [name, type] of available) {
    if (allowed.get(name) === type) exact.set(name, type);
  }
  return exact;
}

function assertSafeOrigin(url: URL): void {
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    (url.pathname !== "" && url.pathname !== "/") ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new GatewayError(
      "INVALID_INSTANCE_URL",
      "EASYPANEL_URL must be a bare HTTPS origin without credentials, path, query, or fragment",
    );
  }
}

function inspectKey(kind: ServiceKind): ProcedureKey {
  if (kind === "postgres") return "inspect_postgres";
  if (kind === "redis") return "inspect_redis";
  return "inspect_app";
}

function createKey(kind: ServiceKind): ProcedureKey {
  if (kind === "postgres") return "create_postgres";
  if (kind === "redis") return "create_redis";
  return "create_app";
}

function destroyKey(kind: ServiceKind): ProcedureKey {
  if (kind === "postgres") return "destroy_postgres";
  if (kind === "redis") return "destroy_redis";
  return "destroy_app";
}

function toSupportedKind(value: string | undefined): ServiceKind | undefined {
  return value === "app" || value === "postgres" || value === "redis" ? value : undefined;
}

function requireServiceRecord(
  raw: unknown,
  project: string,
  service: string,
  kind: ServiceKind,
): Record<string, unknown> {
  const value = requireRecord(raw);
  assertTargetOwnership(value, project, service);
  if (requireSafeEnumLikeField(value, "type", 32) !== kind) targetMismatch();
  requireBooleanField(value, "enabled");
  return value;
}

function normalizeOptionalSource(raw: unknown): ServiceSource | undefined {
  if (raw === undefined || raw === null) return undefined;
  const source = requireRecord(raw);
  const type = requireSafeEnumLikeField(source, "type", 32);
  let projected: unknown;
  if (type === "image") {
    const image = requireStringField(source, "image", 512);
    const digestSeparator = image.indexOf("@");
    if (
      digestSeparator !== -1 &&
      (digestSeparator !== image.lastIndexOf("@") ||
        !/^@[A-Za-z][A-Za-z0-9_+.-]*:[A-Fa-f0-9]{32,}$/.test(
          image.slice(digestSeparator),
        ))
    ) {
      invalidUpstream();
    }
    projected = { type: "image", image };
  } else if (type === "github") {
    projected = {
      type: "git",
      repository: `${requireRepositorySegment(source, "owner")}/${requireRepositorySegment(source, "repo")}`,
      ref: requireStringField(source, "ref", 256),
      path: requireStringField(source, "path", 512),
    };
  } else {
    throw new GatewayError(
      "UNSUPPORTED_SERVICE_SOURCE",
      "The service source type is not supported by this MCP",
    );
  }
  return parseProjected(SourceSchema, projected) as ServiceSource;
}

function normalizeOptionalResources(raw: unknown): Resources | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = requireRecord(raw);
  return parseProjected(ResourcesSchema, {
    memoryReservationMb: requireFiniteNumberField(value, "memoryReservation"),
    memoryLimitMb: requireFiniteNumberField(value, "memoryLimit"),
    cpuReservation: requireFiniteNumberField(value, "cpuReservation"),
    cpuLimit: requireFiniteNumberField(value, "cpuLimit"),
  }) as Resources;
}

function normalizeOptionalDeploy(raw: unknown): DeploySettings | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = requireRecord(raw);
  return parseProjected(DeploySettingsSchema, {
    replicas: requireFiniteNumberField(value, "replicas"),
    zeroDowntime: requireBooleanField(value, "zeroDowntime"),
  }) as DeploySettings;
}

function normalizeOptionalHealthcheck(raw: unknown): Healthcheck | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  const value = requireRecord(raw);
  return parseProjected(HealthcheckSchema, {
    path: requireStringField(value, "path", 512),
    port: requireFiniteNumberField(value, "port"),
    intervalSeconds: requireFiniteNumberField(value, "intervalSeconds"),
    timeoutSeconds: requireFiniteNumberField(value, "timeoutSeconds"),
  }) as Healthcheck;
}

interface NormalizedDomainRecord {
  id: string;
  domain: ServiceDomain;
}

function normalizeDomainRecords(
  raw: unknown,
  project: string,
  service: string,
): NormalizedDomainRecord[] {
  const records = requireArray(raw, MAX_DOMAINS).map((rawDomain) => {
    const entry = requireRecord(rawDomain);
    const id = requireOpaqueIdField(entry, "id");
    if (entry.destinationType !== "service") targetMismatch();
    const destination = requireRecordField(entry, "serviceDestination");
    assertTargetOwnership(destination, project, service);
    if (
      entry.path !== "/" ||
      entry.wildcard !== false ||
      destination.path !== "/" ||
      destination.protocol !== "http"
    ) {
      throw new GatewayError(
        "UNSUPPORTED_DOMAIN_SHAPE",
        "The domain shape is not supported by this MCP",
      );
    }
    const domain = parseProjected(DomainSchema, {
      host: requireStringField(entry, "host", 253),
      port: requireFiniteNumberField(destination, "port"),
      https: requireBooleanField(entry, "https"),
    }) as ServiceDomain;
    return { id, domain };
  });
  if (
    new Set(records.map(({ id }) => id)).size !== records.length ||
    new Set(records.map(({ domain }) => domain.host)).size !== records.length
  ) {
    invalidUpstream();
  }
  return records;
}

function normalizeDomains(raw: unknown, project: string, service: string): ServiceDomain[] {
  return normalizeDomainRecords(raw, project, service).map(({ domain }) => domain);
}

interface DeploymentExpectation {
  expectedId?: string;
  project?: string;
  service?: string;
  expectedType?: string;
}

function normalizeDeployment(
  raw: unknown,
  expectation: DeploymentExpectation,
): DeploymentSummary & { createdAt: string } {
  const value = requireRecord(raw);
  const id = requireOpaqueIdField(value, "id");
  if (expectation.expectedId && id !== expectation.expectedId) targetMismatch();
  const project = requireIdentifierField(value, "projectName");
  const service = requireIdentifierField(value, "serviceName");
  if (expectation.project && project !== expectation.project) targetMismatch();
  if (expectation.service && service !== expectation.service) targetMismatch();
  const type = requireSafeEnumLikeField(value, "type", 32);
  if (expectation.expectedType && type !== expectation.expectedType) targetMismatch();
  const status = requireNormalizedStatusField(value, "status");
  const createdAt = requireIsoDateField(value, "createdAt");
  const finishedAt = optionalCompatibleIsoDateFields(value, "finishedAt", "completedAt");
  return {
    id,
    project,
    service,
    status,
    createdAt,
    ...(finishedAt ? { finishedAt } : {}),
  };
}

function assertMutationAcknowledgement(
  raw: unknown,
  expectation: MutationExpectation,
): void {
  const value = requireRecord(raw);
  assertExplicitSuccess(value);

  if (
    expectation.requestId !== undefined &&
    requireOpaqueIdField(value, "clientRequestId") !== expectation.requestId
  ) {
    targetMismatch();
  }

  if (expectation.service) {
    if (!expectation.project) invalidUpstream();
    assertTargetOwnership(value, expectation.project, expectation.service);
    if (
      expectation.kind &&
      requireSafeEnumLikeField(value, "type", 32) !== expectation.kind
    ) {
      targetMismatch();
    }
    return;
  }

  if (expectation.project) {
    const keys = ["name", "projectName"].filter((key) => Object.hasOwn(value, key));
    if (keys.length === 0) invalidUpstream();
    const projects = keys.map((key) => requireIdentifierField(value, key));
    const returnedProject = projects[0] as string;
    if (projects.some((project) => project !== returnedProject)) invalidUpstream();
    if (returnedProject !== expectation.project) targetMismatch();
    return;
  }
  invalidUpstream();
}

function assertExplicitSuccess(value: Record<string, unknown>): void {
  const keys = ["success", "ok"].filter((key) => Object.hasOwn(value, key));
  if (
    keys.length === 0 ||
    keys.some((key) => value[key] !== true)
  ) {
    invalidUpstream();
  }
}

function requireLifecycleOperation(value: Record<string, unknown>): LifecycleOperation {
  const keys = ["operation", "action"].filter((key) => Object.hasOwn(value, key));
  if (keys.length === 0) invalidUpstream();
  const operations = keys.map((key) => requireSafeEnumLikeField(value, key, 16));
  const operation = operations[0];
  if (
    operation === undefined ||
    operations.some((entry) => entry !== operation) ||
    (operation !== "start" && operation !== "stop" && operation !== "restart")
  ) {
    invalidUpstream();
  }
  return operation;
}

function registerEnvValues(document: string, secrets: SecretRegistry): void {
  let entries: Array<{ name: string; value: string }>;
  try {
    entries = EnvDocument.parse(document).entries();
  } catch {
    invalidUpstream();
  }
  const values = entries.map(({ value }) => value);
  if (
    values.length > MAX_SECRETS_PER_RESPONSE ||
    values.reduce((total, value) => total + Buffer.byteLength(value, "utf8"), 0) >
      MAX_SECRET_BYTES_PER_RESPONSE
  ) {
    invalidUpstream();
  }
  for (const { name, value } of entries) {
    const bytes = Buffer.byteLength(value, "utf8");
    if (bytes > 65_536 || (isSensitiveEnvName(name) && bytes < 8)) invalidUpstream();
    secrets.add(value);
  }
}

function registerSensitiveFields(value: unknown, secrets: SecretRegistry): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const discovered = new Set<string>();
  let visited = 0;
  let enqueued = 1;
  let secretBytes = 0;
  const countChild = (depth: number): void => {
    enqueued += 1;
    if (enqueued > MAX_SENSITIVE_SCAN_NODES || depth > MAX_SENSITIVE_SCAN_DEPTH) {
      invalidUpstream();
    }
  };
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) break;
    if (++visited > MAX_SENSITIVE_SCAN_NODES || current.depth > MAX_SENSITIVE_SCAN_DEPTH) {
      invalidUpstream();
    }
    if (Array.isArray(current.value)) {
      if (current.value.length > MAX_SENSITIVE_CONTAINER_ENTRIES) invalidUpstream();
      for (const entry of current.value) {
        const depth = current.depth + 1;
        countChild(depth);
        pending.push({ value: entry, depth });
      }
      continue;
    }
    if (!current.value || typeof current.value !== "object") continue;
    const record = current.value as Record<string, unknown>;
    let propertyCount = 0;
    for (const key in record) {
      if (!Object.hasOwn(record, key)) continue;
      propertyCount += 1;
      if (propertyCount > MAX_SENSITIVE_CONTAINER_ENTRIES) invalidUpstream();
      const entry = record[key];
      const depth = current.depth + 1;
      countChild(depth);
      if (isSensitiveKey(key) && typeof entry === "string") {
        if (isEnvironmentDocumentKey(key)) continue;
        if (!discovered.has(entry)) {
          const bytes = Buffer.byteLength(entry, "utf8");
          if (bytes < 8 || bytes > 65_536) invalidUpstream();
          discovered.add(entry);
          secretBytes += bytes;
          if (
            discovered.size > MAX_SECRETS_PER_RESPONSE ||
            secretBytes > MAX_SECRET_BYTES_PER_RESPONSE
          ) {
            invalidUpstream();
          }
        }
      } else {
        pending.push({ value: entry, depth });
      }
    }
  }
  for (const secret of discovered) secrets.add(secret);
}

function isEnvironmentDocumentKey(key: string): boolean {
  return /^env(?:ironment)?(?:document|vars?)?$/i.test(key);
}

function hasErrorEnvelope(body: unknown): boolean {
  return isRecord(body) && Object.hasOwn(body, "error");
}

function unwrapEnvelope(body: unknown, flavor: ApiFlavor): unknown {
  const record = requireRecord(body);
  if (flavor === "rpc") {
    if (!Object.hasOwn(record, "json")) invalidUpstream();
    return record.json;
  }
  if (flavor !== "trpc") invalidUpstream();
  const result = requireRecordField(record, "result");
  const data = requireRecordField(result, "data");
  if (!Object.hasOwn(data, "json")) invalidUpstream();
  return data.json;
}

function requireVersion(value: unknown): string {
  const record = requireRecord(value);
  const versions = ["version", "currentVersion", "installedVersion"]
    .filter((key) => Object.hasOwn(record, key))
    .map((key) => requireStringField(record, key, 96));
  if (versions.length === 0 || versions.some((version) => !SAFE_VERSION_PATTERN.test(version))) {
    invalidUpstream();
  }
  const first = versions[0] as string;
  if (versions.some((version) => version !== first)) invalidUpstream();
  return first;
}

function normalizeOptionalStatus(
  value: Record<string, unknown>,
  keys: readonly string[],
): NormalizedStatus {
  const present = keys.filter((key) => Object.hasOwn(value, key));
  if (present.length === 0) return "unknown";
  const statuses = present.map((key) => requireNormalizedStatusField(value, key));
  const first = statuses[0] as NormalizedStatus;
  if (statuses.some((status) => status !== first)) invalidUpstream();
  return first;
}

function normalizeOptionalHealth(
  value: Record<string, unknown>,
): "healthy" | "unhealthy" | "unknown" {
  if (!Object.hasOwn(value, "healthStatus")) return "unknown";
  const raw = requireStringField(value, "healthStatus", 32).toLowerCase();
  if (["healthy", "passing", "ok", "up"].includes(raw)) return "healthy";
  if (["unhealthy", "failing", "error", "down"].includes(raw)) return "unhealthy";
  if (["unknown", "pending", "starting"].includes(raw)) return "unknown";
  invalidUpstream();
}

function normalizeOptionalReadiness(
  value: Record<string, unknown>,
): "ready" | "not_ready" | "unknown" {
  const candidates: Array<"ready" | "not_ready" | "unknown"> = [];
  if (Object.hasOwn(value, "ready")) {
    candidates.push(requireBooleanField(value, "ready") ? "ready" : "not_ready");
  }
  if (Object.hasOwn(value, "readiness")) {
    const raw = requireStringField(value, "readiness", 32).toLowerCase();
    if (raw === "ready") candidates.push("ready");
    else if (["not_ready", "not-ready", "not ready", "unready"].includes(raw)) {
      candidates.push("not_ready");
    } else if (["unknown", "pending", "starting"].includes(raw)) {
      candidates.push("unknown");
    } else {
      invalidUpstream();
    }
  }
  if (candidates.length === 0) return "unknown";
  const first = candidates[0] as "ready" | "not_ready" | "unknown";
  if (candidates.some((candidate) => candidate !== first)) invalidUpstream();
  return first;
}

function optionalCompatibleIsoDateFields(
  value: Record<string, unknown>,
  firstKey: string,
  secondKey: string,
): string | undefined {
  const first = optionalIsoDateField(value, firstKey);
  const second = optionalIsoDateField(value, secondKey);
  if (first && second && first !== second) invalidUpstream();
  return first ?? second;
}

function optionalIsoDateField(
  value: Record<string, unknown>,
  key: string,
): string | undefined {
  if (!Object.hasOwn(value, key) || value[key] === null) return undefined;
  const raw = requireStringField(value, key, 64);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(raw)
  ) {
    invalidUpstream();
  }
  const timestamp = Date.parse(raw);
  if (!Number.isFinite(timestamp)) invalidUpstream();
  return new Date(timestamp).toISOString();
}

function requireIsoDateField(value: Record<string, unknown>, key: string): string {
  const normalized = optionalIsoDateField(value, key);
  if (!normalized) invalidUpstream();
  return normalized;
}

function assertTargetOwnership(
  value: Record<string, unknown>,
  project: string,
  service: string,
): void {
  if (
    requireIdentifierField(value, "projectName") !== project ||
    requireServiceNameField(value) !== service
  ) {
    targetMismatch();
  }
}

function requireServiceNameField(value: Record<string, unknown>): string {
  const keys = ["name", "serviceName"].filter((key) => Object.hasOwn(value, key));
  if (keys.length === 0) invalidUpstream();
  const names = keys.map((key) => requireIdentifierField(value, key));
  const first = names[0] as string;
  if (names.some((name) => name !== first)) invalidUpstream();
  return first;
}

function requireRepositorySegment(value: Record<string, unknown>, key: string): string {
  const segment = requireStringField(value, key, 128);
  if (!/^[A-Za-z0-9_.-]+$/.test(segment)) invalidUpstream();
  return segment;
}

function requireIdentifierField(value: Record<string, unknown>, key: string): string {
  const identifier = requireStringField(value, key, 63);
  if (!IDENTIFIER_PATTERN.test(identifier)) invalidUpstream();
  return identifier;
}

function requireOpaqueIdField(value: Record<string, unknown>, key: string): string {
  const id = requireStringField(value, key, 128);
  if (!OPAQUE_ID_PATTERN.test(id)) invalidUpstream();
  return id;
}

function requireSafeEnumLikeField(
  value: Record<string, unknown>,
  key: string,
  maximum: number,
): string {
  const entry = requireStringField(value, key, maximum);
  if (!/^[a-z][a-z0-9_-]*$/.test(entry)) invalidUpstream();
  return entry;
}

function requireNormalizedStatusField(
  value: Record<string, unknown>,
  key: string,
): NormalizedStatus {
  const status = requireStringField(value, key, 64);
  if (!/^[A-Za-z0-9_. -]+$/.test(status) || status.trim() !== status) invalidUpstream();
  switch (status.toLowerCase()) {
    case "running":
    case "active":
    case "healthy":
    case "up":
    case "ready":
    case "done":
    case "success":
    case "succeeded":
    case "completed":
      return "running";
    case "stopped":
    case "inactive":
    case "disabled":
    case "down":
    case "exited":
      return "stopped";
    case "deploying":
    case "pending":
    case "queued":
    case "building":
    case "starting":
    case "updating":
    case "processing":
      return "deploying";
    case "error":
    case "failed":
    case "failure":
    case "unhealthy":
    case "killed":
    case "cancelled":
    case "canceled":
    case "rejected":
    case "timed out":
    case "timeout":
      return "error";
    default:
      return "unknown";
  }
}

function requireLifecycleActionStatusField(
  value: Record<string, unknown>,
  key: string,
): LifecycleActionStatus {
  const status = requireStringField(value, key, 64);
  if (!/^[A-Za-z0-9_. -]+$/.test(status) || status.trim() !== status) invalidUpstream();
  switch (status.toLowerCase()) {
    case "success":
    case "succeeded":
    case "completed":
    case "done":
      return "succeeded";
    case "failed":
    case "failure":
    case "error":
    case "cancelled":
    case "canceled":
      return "failed";
    case "pending":
    case "queued":
    case "running":
    case "processing":
    case "deploying":
      return "pending";
    case "unknown":
      return "unknown";
    default:
      invalidUpstream();
  }
}

function requireStringField(
  value: Record<string, unknown>,
  key: string,
  maximum: number,
  allowEmpty = false,
): string {
  const entry = value[key];
  if (
    typeof entry !== "string" ||
    entry.length > maximum ||
    (!allowEmpty && entry.length === 0) ||
    entry.includes("\u0000")
  ) {
    invalidUpstream();
  }
  return entry;
}

function extractWebhookToken(value: Record<string, unknown>): string {
  const keys = ["token", "deployToken", "deployWebhook", "webhookToken"].filter((key) =>
    Object.hasOwn(value, key),
  );
  if (keys.length === 0) invalidUpstream();
  const values = keys.map((key) => requireStringField(value, key, 512));
  const first = values[0] as string;
  if (values.some((entry) => entry !== first)) invalidUpstream();
  if (
    Buffer.byteLength(first, "utf8") < 16 ||
    /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(first)
  ) {
    invalidUpstream();
  }
  return first;
}

function requireMutationId(raw: unknown): string {
  const value = requireRecord(raw);
  const keys = ["id", "actionId", "deploymentId"].filter((key) =>
    Object.hasOwn(value, key),
  );
  if (keys.length === 0) invalidUpstream();
  const ids = keys.map((key) => requireOpaqueIdField(value, key));
  const first = ids[0] as string;
  if (ids.some((id) => id !== first)) invalidUpstream();
  return first;
}

function requireBooleanField(value: Record<string, unknown>, key: string): boolean {
  const entry = value[key];
  if (typeof entry !== "boolean") invalidUpstream();
  return entry;
}

function requireFiniteNumberField(value: Record<string, unknown>, key: string): number {
  const entry = value[key];
  if (typeof entry !== "number" || !Number.isFinite(entry)) invalidUpstream();
  return entry;
}

function requireSafeIntegerField(
  value: Record<string, unknown>,
  key: string,
  minimum: number,
  maximum: number,
): number {
  const entry = value[key];
  if (
    typeof entry !== "number" ||
    !Number.isSafeInteger(entry) ||
    entry < minimum ||
    entry > maximum
  ) {
    invalidUpstream();
  }
  return entry;
}

function requireArrayField(
  value: Record<string, unknown>,
  key: string,
  maximum: number,
): unknown[] {
  return requireArray(value[key], maximum);
}

function requireArray(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) invalidUpstream();
  return value;
}

function requireRecordField(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  if (!Object.hasOwn(value, key)) invalidUpstream();
  return requireRecord(value[key]);
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) invalidUpstream();
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseProjected(schema: { safeParse(value: unknown): { success: boolean; data?: unknown } }, value: unknown): unknown {
  const parsed = schema.safeParse(value);
  if (!parsed.success) invalidUpstream();
  return parsed.data;
}

function invalidUpstream(): never {
  throw new GatewayError("INVALID_UPSTREAM_RESPONSE", "Easypanel returned an invalid response");
}

function targetMismatch(): never {
  throw new GatewayError(
    "UPSTREAM_TARGET_MISMATCH",
    "Easypanel returned a response for a different target",
  );
}

/**
 * Cancellation is cleanup only. A hostile or broken stream is allowed to keep
 * its cancellation promise pending, but it must never keep the request itself
 * pending after the response has already been rejected.
 */
function cancelResponseBody(response: Response): void {
  try {
    void response.body?.cancel().catch(() => undefined);
  } catch {
    // Cleanup is best-effort even for a non-conforming Response implementation.
  }
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    void reader.cancel().catch(() => undefined);
  } catch {
    // A hostile stream cannot make cancellation throw into the request path.
  }
}

function awaitWithAbort<T>(operation: PromiseLike<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(new GatewayError("UPSTREAM_TIMEOUT", "Easypanel request timed out"));
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback();
    };
    const onAbort = (): void => {
      finish(() => reject(new GatewayError("UPSTREAM_TIMEOUT", "Easypanel request timed out")));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(operation).then(
      (value) => finish(() => resolve(value)),
      (error: unknown) => finish(() => reject(error)),
    );
  });
}

async function readBoundedBody(
  response: Response,
  maximum: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let chunkCount = 0;
  const cancelOnAbort = (): void => cancelReader(reader);
  if (signal.aborted) cancelOnAbort();
  else signal.addEventListener("abort", cancelOnAbort, { once: true });
  try {
    while (true) {
      const { done, value } = await awaitWithAbort(reader.read(), signal);
      if (done) break;
      chunkCount += 1;
      if (chunkCount > MAX_RESPONSE_CHUNKS) {
        cancelReader(reader);
        throw new GatewayError("RESPONSE_TOO_LARGE", "Easypanel response has too many chunks");
      }
      total += value.byteLength;
      if (total > maximum) {
        cancelReader(reader);
        throw new GatewayError("RESPONSE_TOO_LARGE", "Easypanel response exceeds the safety limit");
      }
      if (value.byteLength > 0) chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancelOnAbort);
    try {
      reader.releaseLock();
    } catch {
      // A non-conforming stream can retain a pending read after cancellation.
      // The request timeout has already been reported and the reader is no
      // longer reachable from this call.
    }
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}
