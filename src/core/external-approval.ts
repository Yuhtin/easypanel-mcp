import { createHmac, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { open, rename, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";

import { canonicalJson, constantTimeEqual } from "./canonical-json.js";
import type { StoredPlan } from "../domain/types.js";
import { ensurePrivateDirectory } from "./secure-path.js";
import { isCriticalPlan } from "./risk.js";

export type ApprovalAction =
  | "apply_service"
  | "deploy_service"
  | "start_service"
  | "stop_service"
  | "restart_service"
  | "destroy_service"
  | "rotate_deploy_webhook";
export type ApprovalPurpose = "approval" | "confirmation";

interface UnsignedApproval {
  version: 2;
  planHash: string;
  purpose: ApprovalPurpose;
  action: ApprovalAction;
  project: string;
  service: string;
  approver: string;
  expiresAt: string;
  nonce: string;
}

interface ApprovalRecord extends UnsignedApproval {
  signature: string;
}

export interface ExternalApprovalOptions {
  directory: string;
  key: string;
  ttlMs?: number;
  now?: () => Date;
}

export class ExternalApprovalError extends Error {
  readonly code:
    | "APPROVAL_CONFIGURATION_INVALID"
    | "APPROVAL_REQUIRED"
    | "CONFIRMATION_REQUIRED"
    | "APPROVAL_INVALID"
    | "APPROVAL_EXPIRED"
    | "APPROVAL_IO_FAILED";

  constructor(code: ExternalApprovalError["code"]) {
    super(code);
    this.name = "ExternalApprovalError";
    this.code = code;
  }
}

const HASH = /^[a-f0-9]{64}$/;
const TARGET = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/;
const APPROVER = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;

export interface ApprovalEvidence {
  approvedBy: string;
  confirmedBy?: string;
}

export class PlanCryptography {
  readonly #key: string;

  constructor(key: string) {
    const bytes = Buffer.byteLength(key, "utf8");
    if (bytes < 32 || bytes > 4_096 || /[\u0000-\u001f\u007f]/.test(key)) {
      throw new ExternalApprovalError("APPROVAL_CONFIGURATION_INVALID");
    }
    this.#key = key;
  }

  signPlan(value: unknown): string {
    return this.#hmac(`plan\0${canonicalJson(value)}`);
  }

  createPlanHash(intentHash: string): string {
    if (!HASH.test(intentHash)) {
      throw new ExternalApprovalError("APPROVAL_CONFIGURATION_INVALID");
    }
    return this.#hmac(
      `plan-generation\0${intentHash}\0${randomBytes(32).toString("hex")}`,
    );
  }

  signApproval(value: UnsignedApproval): string {
    return this.#hmac(`approval\0${canonicalJson(value)}`);
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }
}

export class ExternalApprovalStore {
  readonly #directory: string;
  readonly #crypto: PlanCryptography;
  readonly #ttlMs: number;
  readonly #now: () => Date;

  constructor(options: ExternalApprovalOptions) {
    if (
      !options.directory ||
      options.directory.includes("\u0000") ||
      !Number.isSafeInteger(options.ttlMs ?? 300_000) ||
      (options.ttlMs ?? 300_000) < 30_000 ||
      (options.ttlMs ?? 300_000) > 900_000
    ) {
      throw new ExternalApprovalError("APPROVAL_CONFIGURATION_INVALID");
    }
    this.#directory = resolve(options.directory);
    this.#crypto = new PlanCryptography(options.key);
    this.#ttlMs = options.ttlMs ?? 300_000;
    this.#now = options.now ?? (() => new Date());
  }

  instruction(
    plan: Pick<StoredPlan, "planHash" | "target" | "operation" | "actions">,
    purpose: ApprovalPurpose = "approval",
  ): string {
    const action = approvalActionForPlan(plan);
    return [
      "easypanel-mcp-approve",
      "--plan",
      plan.planHash,
      "--action",
      action,
      "--purpose",
      purpose,
      "--project",
      plan.target.project,
      "--service",
      plan.target.service,
      "--approver",
      "REQUIRED_HUMAN_IDENTITY",
    ].join(" ");
  }

  async create(input: {
    planHash: string;
    purpose: ApprovalPurpose;
    action: ApprovalAction;
    project: string;
    service: string;
    approver: string;
  }): Promise<void> {
    validateIdentity(input);
    await this.#secureDirectory();
    const now = this.#now().getTime();
    if (!Number.isFinite(now)) {
      throw new ExternalApprovalError("APPROVAL_CONFIGURATION_INVALID");
    }
    const unsigned: UnsignedApproval = {
      version: 2,
      ...input,
      expiresAt: new Date(now + this.#ttlMs).toISOString(),
      nonce: randomBytes(24).toString("hex"),
    };
    const record: ApprovalRecord = {
      ...unsigned,
      signature: this.#crypto.signApproval(unsigned),
    };
    const path = this.#path(input.planHash, input.purpose);
    try {
      const handle = await open(
        path,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_WRONLY |
          constants.O_NOFOLLOW,
        0o600,
      );
      try {
        const metadata = await handle.stat();
        if (
          !metadata.isFile() ||
          metadata.nlink !== 1 ||
          (typeof process.getuid === "function" && metadata.uid !== process.getuid())
        ) {
          throw new ExternalApprovalError("APPROVAL_IO_FAILED");
        }
        const line = `${JSON.stringify(record)}\n`;
        const written = await handle.write(line, null, "utf8");
        if (written.bytesWritten !== Buffer.byteLength(line, "utf8")) {
          throw new ExternalApprovalError("APPROVAL_IO_FAILED");
        }
        await handle.sync();
        await handle.chmod(0o600);
        if (((await handle.stat()).mode & 0o077) !== 0) {
          throw new ExternalApprovalError("APPROVAL_IO_FAILED");
        }
      } finally {
        await handle.close();
      }
    } catch {
      throw new ExternalApprovalError("APPROVAL_IO_FAILED");
    }
  }

  async consume(
    plan: Pick<StoredPlan, "planHash" | "target" | "operation" | "actions">,
  ): Promise<ApprovalEvidence> {
    validateIdentity({ planHash: plan.planHash, ...plan.target });
    await this.#secureDirectory();
    const approvedBy = await this.#consumeArtifact(plan, "approval");
    if (isCriticalPlan(plan)) {
      const confirmedBy = await this.#consumeArtifact(plan, "confirmation");
      if (confirmedBy === approvedBy) {
        throw new ExternalApprovalError("APPROVAL_INVALID");
      }
      return {
        approvedBy,
        confirmedBy,
      };
    }
    return { approvedBy };
  }

  async #consumeArtifact(
    plan: Pick<StoredPlan, "planHash" | "target" | "operation" | "actions">,
    purpose: ApprovalPurpose,
  ): Promise<string> {
    const source = this.#path(plan.planHash, purpose);
    const claimed = join(
      this.#directory,
      `.${plan.planHash}.${purpose}.${process.pid}.${randomBytes(8).toString("hex")}.claimed`,
    );
    try {
      await rename(source, claimed);
    } catch (error: unknown) {
      if (hasCode(error, "ENOENT")) {
        throw new ExternalApprovalError(
          purpose === "confirmation" ? "CONFIRMATION_REQUIRED" : "APPROVAL_REQUIRED",
        );
      }
      throw new ExternalApprovalError("APPROVAL_IO_FAILED");
    }

    try {
      const handle = await open(
        claimed,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      let text: string;
      try {
        const metadata = await handle.stat();
        if (
          !metadata.isFile() ||
          metadata.nlink !== 1 ||
          (metadata.mode & 0o077) !== 0 ||
          metadata.size > 8192 ||
          (typeof process.getuid === "function" && metadata.uid !== process.getuid())
        ) {
          throw new ExternalApprovalError("APPROVAL_INVALID");
        }
        text = await handle.readFile("utf8");
      } finally {
        await handle.close();
      }
      const record = parseRecord(text);
      const { signature, ...unsigned } = record;
      const expectedSignature = this.#crypto.signApproval(unsigned);
      const expectedAction = approvalActionForPlan(plan);
      if (
        !constantTimeEqual(signature, expectedSignature) ||
        record.planHash !== plan.planHash ||
        record.purpose !== purpose ||
        record.project !== plan.target.project ||
        record.service !== plan.target.service ||
        record.action !== expectedAction
      ) {
        throw new ExternalApprovalError("APPROVAL_INVALID");
      }
      const now = this.#now().getTime();
      if (!Number.isFinite(now)) {
        throw new ExternalApprovalError("APPROVAL_CONFIGURATION_INVALID");
      }
      if (now >= Date.parse(record.expiresAt)) {
        throw new ExternalApprovalError("APPROVAL_EXPIRED");
      }
      return record.approver;
    } finally {
      await unlink(claimed).catch(() => undefined);
    }
  }

  #path(planHash: string, purpose: ApprovalPurpose): string {
    if (!HASH.test(planHash)) throw new ExternalApprovalError("APPROVAL_INVALID");
    return join(this.#directory, `${planHash}.${purpose}.json`);
  }

  async #secureDirectory(): Promise<void> {
    try {
      await ensurePrivateDirectory(this.#directory);
    } catch (error: unknown) {
      if (error instanceof ExternalApprovalError) throw error;
      throw new ExternalApprovalError("APPROVAL_IO_FAILED");
    }
  }
}

export function approvalActionForPlan(
  plan: Pick<StoredPlan, "operation" | "actions">,
): ApprovalAction {
  if (plan.operation === "deploy") return "deploy_service";
  if (plan.operation === "start") return "start_service";
  if (plan.operation === "stop") return "stop_service";
  if (plan.operation === "restart") return "restart_service";
  if (plan.operation === "rotate_deploy_webhook") return "rotate_deploy_webhook";
  if (plan.actions.some((action) => action.type === "deploy_service")) {
    return "deploy_service";
  }
  if (plan.actions.some((action) => action.type === "start_service")) {
    return "start_service";
  }
  if (plan.actions.some((action) => action.type === "stop_service")) {
    return "stop_service";
  }
  if (plan.actions.some((action) => action.type === "restart_service")) {
    return "restart_service";
  }
  if (plan.actions.some((action) => action.type === "rotate_deploy_webhook")) {
    return "rotate_deploy_webhook";
  }
  if (plan.actions.some((action) => action.type === "destroy_service")) {
    return "destroy_service";
  }
  return "apply_service";
}

function validateIdentity(input: {
  planHash: string;
  project: string;
  service: string;
  approver?: string;
}): void {
  if (
    !HASH.test(input.planHash) ||
    !TARGET.test(input.project) ||
    !TARGET.test(input.service) ||
    (input.approver !== undefined &&
      (!APPROVER.test(input.approver) || input.approver === "REQUIRED_HUMAN_IDENTITY"))
  ) {
    throw new ExternalApprovalError("APPROVAL_INVALID");
  }
}

function parseRecord(text: string): ApprovalRecord {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ExternalApprovalError("APPROVAL_INVALID");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ExternalApprovalError("APPROVAL_INVALID");
  }
  const record = value as Partial<ApprovalRecord>;
  if (
    record.version !== 2 ||
    typeof record.planHash !== "string" ||
    (record.purpose !== "approval" && record.purpose !== "confirmation") ||
    typeof record.action !== "string" ||
    ![
      "apply_service",
      "deploy_service",
      "start_service",
      "stop_service",
      "restart_service",
      "destroy_service",
      "rotate_deploy_webhook",
    ].includes(
      record.action,
    ) ||
    typeof record.project !== "string" ||
    typeof record.service !== "string" ||
    typeof record.approver !== "string" ||
    typeof record.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(record.expiresAt)) ||
    typeof record.nonce !== "string" ||
    !/^[a-f0-9]{48}$/.test(record.nonce) ||
    typeof record.signature !== "string" ||
    !HASH.test(record.signature)
  ) {
    throw new ExternalApprovalError("APPROVAL_INVALID");
  }
  validateIdentity({
    planHash: record.planHash,
    project: record.project,
    service: record.service,
    approver: record.approver,
  });
  return record as ApprovalRecord;
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
