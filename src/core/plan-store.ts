import { TargetSchema } from "../domain/schemas.js";
import type { ApplyResult, StoredPlan } from "../domain/types.js";
import { canonicalJson, constantTimeEqual } from "./canonical-json.js";
export { isCriticalPlan } from "./risk.js";

export type NewStoredPlan = Omit<
  StoredPlan,
  "createdAt" | "expiresAt" | "appliedAt" | "result"
> & {
  createdAt?: string;
};

export type PlanClaim =
  | { kind: "execute"; plan: StoredPlan }
  | { kind: "replay"; result: ApplyResult };

export interface PlanStoreOptions {
  ttlMs: number;
  replayTtlMs?: number;
  maxEntries?: number;
  maxEntriesPerTarget?: number;
  now?: () => Date;
}

interface PlanEntry {
  plan: StoredPlan;
  identity: string;
  intentIdentity: string;
  applying: boolean;
}

interface CompletedEntry {
  plan: StoredPlan;
  replayExpiresAt: number;
}

export type PlanStoreErrorCode =
  | "PLAN_INVALID"
  | "PLAN_HASH_CONFLICT"
  | "PLAN_NOT_FOUND"
  | "PLAN_EXPIRED"
  | "PLAN_IN_PROGRESS"
  | "PLAN_CAPACITY"
  | "PLAN_UNCERTAIN"
  | "PLAN_NOT_CLAIMED"
  | "PLAN_RESULT_INVALID";

export class PlanStoreError extends Error {
  readonly code: PlanStoreErrorCode;

  constructor(code: PlanStoreErrorCode) {
    super(code);
    this.name = "PlanStoreError";
    this.code = code;
  }
}

const HASH = /^[a-f0-9]{64}$/;

function planIdentity(plan: NewStoredPlan | StoredPlan): string {
  return canonicalJson({
    planHash: plan.planHash,
    intentHash: plan.intentHash,
    target: plan.target,
    actions: plan.actions,
    noChanges: plan.noChanges,
    spec: plan.spec,
    operation: plan.operation,
    preconditionHash: plan.preconditionHash,
    capabilityHash: plan.capabilityHash,
    operationState: plan.operationState,
    approval: plan.approval,
    confirmation: plan.confirmation,
  });
}

function planIntentIdentity(plan: NewStoredPlan | StoredPlan): string {
  return canonicalJson({
    intentHash: plan.intentHash,
    target: plan.target,
    actions: plan.actions,
    noChanges: plan.noChanges,
    spec: plan.spec,
    operation: plan.operation,
    preconditionHash: plan.preconditionHash,
    capabilityHash: plan.capabilityHash,
    operationState: plan.operationState,
  });
}

function clonePlan(plan: StoredPlan): StoredPlan {
  return structuredClone(plan);
}

function cloneResult(result: ApplyResult, replay: boolean): ApplyResult {
  return {
    ...structuredClone(result),
    ...(replay ? { changed: false, appliedActions: [] } : {}),
    idempotentReplay: replay,
  };
}

export class PlanStore {
  readonly #ttlMs: number;
  readonly #replayTtlMs: number;
  readonly #maxEntries: number;
  readonly #maxEntriesPerTarget: number;
  readonly #now: () => Date;
  readonly #entries = new Map<string, PlanEntry>();
  // Completed generations are a bounded replay cache, never active-plan quota.
  // Eviction only loses a no-mutation replay response; it cannot authorize apply.
  readonly #completed = new Map<string, CompletedEntry>();
  // A plan hash identifies one externally approved generation. The deterministic
  // intent hash is separate so a failed/uncertain generation blocks the same
  // desired transition, while a completed generation may be planned again after
  // the state cycles back later.
  readonly #uncertainPlanHashes = new Set<string>();
  readonly #uncertainIntentHashes = new Set<string>();
  #uncertainOverflow = false;

  constructor(options: PlanStoreOptions) {
    if (
      !Number.isSafeInteger(options.ttlMs) ||
      options.ttlMs < 1 ||
      (options.replayTtlMs !== undefined &&
        (!Number.isSafeInteger(options.replayTtlMs) || options.replayTtlMs < 1))
      || (options.maxEntries !== undefined &&
        (!Number.isSafeInteger(options.maxEntries) || options.maxEntries < 1))
      || (options.maxEntriesPerTarget !== undefined &&
        (!Number.isSafeInteger(options.maxEntriesPerTarget) || options.maxEntriesPerTarget < 1))
    ) {
      throw new PlanStoreError("PLAN_INVALID");
    }
    this.#ttlMs = options.ttlMs;
    this.#replayTtlMs = options.replayTtlMs ?? 86_400_000;
    this.#maxEntries = options.maxEntries ?? 256;
    this.#maxEntriesPerTarget = options.maxEntriesPerTarget ?? 16;
    this.#now = options.now ?? (() => new Date());
  }

  save(input: NewStoredPlan): StoredPlan {
    this.cleanup();
    if (
      !HASH.test(input.planHash) ||
      !HASH.test(input.intentHash) ||
      !HASH.test(input.preconditionHash) ||
      !HASH.test(input.capabilityHash)
    ) {
      throw new PlanStoreError("PLAN_INVALID");
    }
    const target = TargetSchema.safeParse(input.target);
    if (!target.success) {
      throw new PlanStoreError("PLAN_INVALID");
    }

    const identity = planIdentity(input);
    const intentIdentity = planIntentIdentity(input);
    if (
      this.#uncertainPlanHashes.has(input.planHash) ||
      this.#uncertainIntentHashes.has(input.intentHash)
    ) {
      throw new PlanStoreError("PLAN_UNCERTAIN");
    }
    if (this.#uncertainOverflow) throw new PlanStoreError("PLAN_CAPACITY");
    const existing = this.#entries.get(input.planHash);
    if (existing) {
      if (existing.identity !== identity || existing.plan.result) {
        throw new PlanStoreError("PLAN_HASH_CONFLICT");
      }
      return clonePlan(existing.plan);
    }
    if (this.#completed.has(input.planHash)) {
      throw new PlanStoreError("PLAN_HASH_CONFLICT");
    }

    const activeIntent = [...this.#entries.values()].find(
      (entry) => entry.plan.intentHash === input.intentHash && !entry.plan.result,
    );
    if (activeIntent) {
      if (activeIntent.intentIdentity !== intentIdentity) {
        throw new PlanStoreError("PLAN_HASH_CONFLICT");
      }
      return clonePlan(activeIntent.plan);
    }

    if (this.#entries.size >= this.#maxEntries) {
      throw new PlanStoreError("PLAN_CAPACITY");
    }
    const targetKey = `${target.data.project}/${target.data.service}`;
    const targetCount = [...this.#entries.values()].filter(
      (entry) => `${entry.plan.target.project}/${entry.plan.target.service}` === targetKey,
    ).length;
    if (targetCount >= this.#maxEntriesPerTarget) {
      throw new PlanStoreError("PLAN_CAPACITY");
    }

    const now = this.#nowMs();
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + this.#ttlMs).toISOString();
    const base = structuredClone(input);
    const plan: StoredPlan = {
      ...base,
      target: target.data as { project: string; service: string },
      createdAt,
      expiresAt,
    };

    this.#entries.set(plan.planHash, {
      plan,
      identity,
      intentIdentity,
      applying: false,
    });
    return clonePlan(plan);
  }

  get(planHash: string): StoredPlan | undefined {
    if (!HASH.test(planHash)) throw new PlanStoreError("PLAN_INVALID");
    if (this.#uncertainPlanHashes.has(planHash)) throw new PlanStoreError("PLAN_UNCERTAIN");
    const entry = this.#entries.get(planHash);
    const now = this.#nowMs();
    if (entry) {
      if (now >= Date.parse(entry.plan.expiresAt) && !entry.applying) {
        this.#entries.delete(planHash);
        throw new PlanStoreError("PLAN_EXPIRED");
      }
      this.cleanup();
      return clonePlan(entry.plan);
    }
    const completed = this.#completed.get(planHash);
    if (!completed) {
      this.cleanup();
      return undefined;
    }
    if (now >= completed.replayExpiresAt) {
      this.#completed.delete(planHash);
      throw new PlanStoreError("PLAN_EXPIRED");
    }
    this.cleanup();
    return clonePlan(completed.plan);
  }

  claim(planHash: string): PlanClaim {
    if (!HASH.test(planHash)) throw new PlanStoreError("PLAN_INVALID");
    if (this.#uncertainPlanHashes.has(planHash)) throw new PlanStoreError("PLAN_UNCERTAIN");
    const now = this.#nowMs();
    const completed = this.#completed.get(planHash);
    if (completed) {
      if (now >= completed.replayExpiresAt) {
        this.#completed.delete(planHash);
        throw new PlanStoreError("PLAN_EXPIRED");
      }
      if (!completed.plan.result) {
        this.#completed.delete(planHash);
        throw new PlanStoreError("PLAN_RESULT_INVALID");
      }
      return { kind: "replay", result: cloneResult(completed.plan.result, true) };
    }
    const entry = this.#entries.get(planHash);
    if (!entry) throw new PlanStoreError("PLAN_NOT_FOUND");

    if (now >= Date.parse(entry.plan.expiresAt)) {
      this.#entries.delete(entry.plan.planHash);
      throw new PlanStoreError("PLAN_EXPIRED");
    }
    if (entry.applying) throw new PlanStoreError("PLAN_IN_PROGRESS");

    entry.applying = true;
    return { kind: "execute", plan: clonePlan(entry.plan) };
  }

  complete(result: ApplyResult): ApplyResult {
    const entry = this.#entries.get(result.planHash);
    if (!entry || !entry.applying) {
      throw new PlanStoreError("PLAN_NOT_CLAIMED");
    }
    const target = TargetSchema.safeParse(result.target);
    if (
      !target.success ||
      target.data.project !== entry.plan.target.project ||
      target.data.service !== entry.plan.target.service ||
      !constantTimeEqual(result.planHash, entry.plan.planHash)
    ) {
      throw new PlanStoreError("PLAN_RESULT_INVALID");
    }

    const storedResult = cloneResult(result, false);
    const completedAt = this.#nowMs();
    entry.plan.result = storedResult;
    entry.plan.appliedAt = new Date(completedAt).toISOString();
    entry.applying = false;
    this.#entries.delete(result.planHash);
    if (this.#completed.size >= this.#maxEntries) {
      const oldest = this.#completed.keys().next().value as string | undefined;
      if (oldest !== undefined) this.#completed.delete(oldest);
    }
    this.#completed.set(result.planHash, {
      plan: clonePlan(entry.plan),
      replayExpiresAt: completedAt + this.#replayTtlMs,
    });
    return cloneResult(storedResult, false);
  }

  release(planHash: string): void {
    const entry = this.#entries.get(planHash);
    if (entry && !entry.plan.result) entry.applying = false;
  }

  /** Poison both this generation and its deterministic intent after an uncertain apply. */
  invalidate(planHash: string): void {
    const entry = this.#entries.get(planHash);
    if (!entry || entry.plan.result) return;
    this.#entries.delete(planHash);
    if (
      this.#uncertainPlanHashes.size >= this.#maxEntries ||
      this.#uncertainIntentHashes.size >= this.#maxEntries
    ) {
      // Never evict an uncertainty marker and accidentally permit a duplicate
      // mutation. Overflow therefore fails all future saves closed; remaining
      // already-active entries may add at most maxEntries further markers.
      this.#uncertainOverflow = true;
    }
    this.#uncertainPlanHashes.add(planHash);
    this.#uncertainIntentHashes.add(entry.plan.intentHash);
  }

  cleanup(): void {
    const now = this.#nowMs();
    for (const [hash, entry] of this.#entries) {
      if (now >= Date.parse(entry.plan.expiresAt) && !entry.applying) {
        this.#entries.delete(hash);
      }
    }
    for (const [hash, entry] of this.#completed) {
      if (now >= entry.replayExpiresAt) this.#completed.delete(hash);
    }
  }

  #nowMs(): number {
    const now = this.#now().getTime();
    if (!Number.isFinite(now)) throw new PlanStoreError("PLAN_INVALID");
    return now;
  }
}
