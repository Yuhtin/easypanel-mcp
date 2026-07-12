import { randomUUID, createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { ProjectNameSchema, ServiceNameSchema } from "../domain/schemas.js";
import type { PlanActionType } from "../domain/types.js";
import { ensurePrivateDirectory } from "./secure-path.js";

export type AuditOutcome = "allowed" | "denied" | "started" | "succeeded" | "failed" | "replayed";

export interface AuditTarget {
  project: string;
  service?: string;
}

export interface AuditEventInput {
  actor: string;
  action: string;
  outcome: AuditOutcome;
  target?: AuditTarget;
  planHash?: string;
  idempotencyKey?: string;
  errorCode?: string;
  durationMs?: number;
  changed?: boolean;
  approvedBy?: string;
  confirmedBy?: string;
  plannedActions?: PlanActionType[];
  appliedActions?: PlanActionType[];
  deploymentId?: string;
  actionId?: string;
}

export interface AuditEvent {
  schemaVersion: 1;
  auditId: string;
  timestamp: string;
  actor: string;
  action: string;
  outcome: AuditOutcome;
  target?: AuditTarget;
  planHash?: string;
  idempotencyKeyHash?: string;
  errorCode?: string;
  durationMs?: number;
  changed?: boolean;
  approvedBy?: string;
  confirmedBy?: string;
  plannedActions?: PlanActionType[];
  appliedActions?: PlanActionType[];
  deploymentId?: string;
  actionId?: string;
}

export interface JsonlAuditLogOptions {
  path: string;
  now?: () => Date;
  maxBytes?: number;
}

export class AuditError extends Error {
  readonly code: "AUDIT_EVENT_INVALID" | "AUDIT_WRITE_FAILED";

  constructor(code: "AUDIT_EVENT_INVALID" | "AUDIT_WRITE_FAILED") {
    super(code);
    this.name = "AuditError";
    this.code = code;
  }
}

const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;
const PLAN_HASH = /^[a-f0-9]{64}$/;
const ERROR_CODE = /^[A-Z0-9_]{1,64}$/;
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const ACTIONS = new Set<PlanActionType>([
  "create_project",
  "create_service",
  "update_source",
  "merge_environment",
  "update_resources",
  "update_deploy",
  "add_domain",
  "remove_domain",
  "update_healthcheck",
  "destroy_service",
  "deploy_service",
  "start_service",
  "stop_service",
  "restart_service",
  "rotate_deploy_webhook",
]);

function hashOpaque(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export class JsonlAuditLog {
  readonly #path: string;
  readonly #now: () => Date;
  readonly #maxBytes: number;
  #tail: Promise<void> = Promise.resolve();

  constructor(options: JsonlAuditLogOptions) {
    const filename = basename(options.path);
    if (
      !options.path ||
      options.path.includes("\u0000") ||
      filename === "." ||
      filename === ".." ||
      (options.maxBytes !== undefined &&
        (!Number.isSafeInteger(options.maxBytes) ||
          options.maxBytes < 1_024 ||
          options.maxBytes > 1_073_741_824))
    ) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    this.#path = options.path;
    this.#now = options.now ?? (() => new Date());
    this.#maxBytes = options.maxBytes ?? 134_217_728;
  }

  append(input: AuditEventInput): Promise<AuditEvent> {
    const operation = this.#tail.then(() => this.#append(input));
    this.#tail = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  #validatedEvent(input: AuditEventInput): AuditEvent {
    // These are declared public identifiers, not free-form payloads. Redacting
    // them by value can destroy attribution when an unrelated env value happens
    // to equal a project/service/actor. Confidential data has no field in this
    // schema and is therefore dropped before this point.
    const actor = input.actor;
    const action = input.action;
    if (!SAFE_LABEL.test(actor) || !SAFE_LABEL.test(action)) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    const approvedBy = input.approvedBy;
    const confirmedBy = input.confirmedBy;
    if (
      (approvedBy !== undefined && !SAFE_LABEL.test(approvedBy)) ||
      (confirmedBy !== undefined && !SAFE_LABEL.test(confirmedBy))
    ) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }

    let target: AuditTarget | undefined;
    if (input.target) {
      const project = ProjectNameSchema.safeParse(input.target.project);
      const service = input.target.service === undefined
        ? undefined
        : ServiceNameSchema.safeParse(input.target.service);
      if (!project.success || (service !== undefined && !service.success)) {
        throw new AuditError("AUDIT_EVENT_INVALID");
      }
      target = {
        project: project.data as string,
        ...(service?.success
          ? { service: service.data as string }
          : {}),
      };
    }

    if (input.planHash !== undefined && !PLAN_HASH.test(input.planHash)) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    if (input.errorCode !== undefined && !ERROR_CODE.test(input.errorCode)) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    if (
      input.durationMs !== undefined &&
      (!Number.isSafeInteger(input.durationMs) || input.durationMs < 0)
    ) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    const plannedActions = validateActions(input.plannedActions);
    const appliedActions = validateActions(input.appliedActions);
    if (input.deploymentId !== undefined && !OPAQUE_ID.test(input.deploymentId)) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }
    if (input.actionId !== undefined && !OPAQUE_ID.test(input.actionId)) {
      throw new AuditError("AUDIT_EVENT_INVALID");
    }

    return {
      schemaVersion: 1,
      auditId: randomUUID(),
      timestamp: this.#now().toISOString(),
      actor,
      action,
      outcome: input.outcome,
      ...(target ? { target } : {}),
      ...(input.planHash ? { planHash: input.planHash } : {}),
      ...(input.idempotencyKey
        ? { idempotencyKeyHash: hashOpaque(input.idempotencyKey) }
        : {}),
      ...(input.errorCode ? { errorCode: input.errorCode } : {}),
      ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
      ...(input.changed !== undefined ? { changed: input.changed } : {}),
      ...(approvedBy !== undefined ? { approvedBy } : {}),
      ...(confirmedBy !== undefined ? { confirmedBy } : {}),
      ...(plannedActions !== undefined ? { plannedActions } : {}),
      ...(appliedActions !== undefined ? { appliedActions } : {}),
      ...(input.deploymentId !== undefined ? { deploymentId: input.deploymentId } : {}),
      ...(input.actionId !== undefined ? { actionId: input.actionId } : {}),
    };
  }

  async #append(input: AuditEventInput): Promise<AuditEvent> {
    const event = this.#validatedEvent(input);
    try {
      const directory = await ensurePrivateDirectory(dirname(this.#path));
      const auditPath = join(directory, basename(this.#path));
      const line = `${JSON.stringify(event)}\n`;
      const lineBytes = Buffer.byteLength(line, "utf8");
      if (lineBytes > 8_192) throw new AuditError("AUDIT_EVENT_INVALID");
      const flags =
        constants.O_APPEND |
        constants.O_CREAT |
        constants.O_WRONLY |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK;
      const handle = await open(auditPath, flags, 0o600);
      try {
        const metadata = await handle.stat();
        if (
          !metadata.isFile() ||
          metadata.nlink !== 1 ||
          !Number.isSafeInteger(metadata.size) ||
          metadata.size > this.#maxBytes - lineBytes ||
          (typeof process.getuid === "function" && metadata.uid !== process.getuid())
        ) {
          throw new AuditError("AUDIT_WRITE_FAILED");
        }
        await handle.chmod(0o600);
        const privateMetadata = await handle.stat();
        if ((privateMetadata.mode & 0o077) !== 0) {
          throw new AuditError("AUDIT_WRITE_FAILED");
        }
        const written = await handle.write(line, null, "utf8");
        if (written.bytesWritten !== Buffer.byteLength(line, "utf8")) {
          throw new AuditError("AUDIT_WRITE_FAILED");
        }
        await handle.sync();
      } finally {
        await handle.close();
      }
      return event;
    } catch (error) {
      if (error instanceof AuditError) throw error;
      throw new AuditError("AUDIT_WRITE_FAILED");
    }
  }
}

function validateActions(actions: PlanActionType[] | undefined): PlanActionType[] | undefined {
  if (
    actions === undefined ||
    actions.length > 128 ||
    actions.some((action) => !ACTIONS.has(action))
  ) {
    if (actions === undefined) return undefined;
    throw new AuditError("AUDIT_EVENT_INVALID");
  }
  return [...actions];
}
