import { AsyncLocalStorage } from "node:async_hooks";

const REDACTED = "[REDACTED]";

const SENSITIVE_KEY =
  /authorization|cookie|credential|env(?:ironment)?(?:document|vars?)?|pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|deploy[_-]?webhook|registry[_-]?(?:auth|password|token)/i;
const SENSITIVE_ENV_NAME =
  /secret|pass(?:word|wd)?|token|credential|private|authorization|cookie|session|access_?key|client_?key|(?:^|_)auth(?:_|$)|api_?key|database_url|redis_url|mongo(?:db)?_url|dsn|connection_string|webhook/i;

export class RedactionError extends Error {
  readonly code = "REDACTION_CAPACITY_EXCEEDED";

  constructor() {
    super("REDACTION_CAPACITY_EXCEEDED");
    this.name = "RedactionError";
  }
}

interface SecretBucket {
  readonly values: Set<string>;
  bytes: number;
  closed: boolean;
}

function bucket(): SecretBucket {
  return { values: new Set<string>(), bytes: 0, closed: false };
}

export class SecretRegistry {
  readonly #base = bucket();
  readonly #scopes = new AsyncLocalStorage<SecretBucket>();
  readonly #maxValues: number;
  readonly #maxBytes: number;
  readonly #scopedMaxValues: number;
  readonly #scopedMaxBytes: number;
  readonly #minimumValueBytes: number;
  readonly #maximumValueBytes: number;
  #baseSealed = false;

  constructor(options: {
    maxValues?: number;
    maxBytes?: number;
    scopedMaxValues?: number;
    scopedMaxBytes?: number;
    minimumValueBytes?: number;
    maximumValueBytes?: number;
  } = {}) {
    if (
      (options.maxValues !== undefined &&
        (!Number.isSafeInteger(options.maxValues) || options.maxValues < 1)) ||
      (options.maxBytes !== undefined &&
        (!Number.isSafeInteger(options.maxBytes) || options.maxBytes < 1)) ||
      (options.scopedMaxValues !== undefined &&
        (!Number.isSafeInteger(options.scopedMaxValues) || options.scopedMaxValues < 1)) ||
      (options.scopedMaxBytes !== undefined &&
        (!Number.isSafeInteger(options.scopedMaxBytes) || options.scopedMaxBytes < 1)) ||
      (options.minimumValueBytes !== undefined &&
        (!Number.isSafeInteger(options.minimumValueBytes) || options.minimumValueBytes < 1)) ||
      (options.maximumValueBytes !== undefined &&
        (!Number.isSafeInteger(options.maximumValueBytes) || options.maximumValueBytes < 1)) ||
      (options.minimumValueBytes !== undefined &&
        options.maximumValueBytes !== undefined &&
        options.minimumValueBytes > options.maximumValueBytes)
    ) {
      throw new RedactionError();
    }
    this.#maxValues = options.maxValues ?? 512;
    this.#maxBytes = options.maxBytes ?? 524_288;
    this.#scopedMaxValues = options.scopedMaxValues ?? options.maxValues ?? 1_024;
    this.#scopedMaxBytes = options.scopedMaxBytes ?? options.maxBytes ?? 2_097_152;
    this.#minimumValueBytes = options.minimumValueBytes ?? 8;
    this.#maximumValueBytes = options.maximumValueBytes ?? 65_536;
  }

  sealBase(): void {
    this.#baseSealed = true;
  }

  async runScoped<T>(operation: () => T | Promise<T>): Promise<T> {
    const current = this.#scopes.getStore();
    if (current) {
      if (current.closed) throw new RedactionError();
      return await operation();
    }

    this.sealBase();
    const scoped = bucket();
    return await this.#scopes.run(scoped, async () => {
      try {
        return await operation();
      } finally {
        scoped.closed = true;
        scoped.values.clear();
        scoped.bytes = 0;
      }
    });
  }

  add(value: string | undefined): void {
    if (!value) return;
    const scoped = this.#scopes.getStore();
    if (scoped?.closed) throw new RedactionError();
    if (!scoped && this.#baseSealed) throw new RedactionError();
    if (this.#base.values.has(value) || scoped?.values.has(value)) return;
    const bytes = Buffer.byteLength(value, "utf8");
    // Very short values cause destructive global substitutions (for example,
    // redacting every "1"). Sensitive short values must instead be rejected by
    // their context-specific input/upstream schema.
    if (bytes < this.#minimumValueBytes) return;
    if (bytes > this.#maximumValueBytes) throw new RedactionError();
    const destination = scoped ?? this.#base;
    const maxValues = scoped ? this.#scopedMaxValues : this.#maxValues;
    const maxBytes = scoped ? this.#scopedMaxBytes : this.#maxBytes;
    if (destination.values.size >= maxValues || destination.bytes + bytes > maxBytes) {
      throw new RedactionError();
    }
    destination.values.add(value);
    destination.bytes += bytes;
  }

  redactText(input: string): string {
    const scoped = this.#scopes.getStore();
    if (scoped?.closed) throw new RedactionError();
    const values = scoped
      ? new Set([...this.#base.values, ...scoped.values])
      : this.#base.values;
    let output = input;
    for (const secret of [...values].sort((left, right) => right.length - left.length)) {
      output = output.split(secret).join(REDACTED);
      try {
        output = output.split(encodeURIComponent(secret)).join(REDACTED);
      } catch {
        // An invalid URI sequence cannot make the raw value safe to expose.
      }
    }
    return output;
  }
}

export function isSensitiveKey(key: string): boolean {
  if (key === "environmentNames") return false;
  return SENSITIVE_KEY.test(key);
}

export function isSensitiveEnvName(name: string): boolean {
  return SENSITIVE_ENV_NAME.test(name);
}

export function redactStructure(
  value: unknown,
  secrets: SecretRegistry,
  seen = new WeakSet<object>(),
): unknown {
  if (typeof value === "string") {
    return secrets.redactText(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => redactStructure(entry, secrets, seen));
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  if (seen.has(value)) {
    return "[CIRCULAR]";
  }
  seen.add(value);

  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    Object.defineProperty(output, key, {
      value: isSensitiveKey(key) ? REDACTED : redactStructure(entry, secrets, seen),
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return output;
}

export function safeErrorCode(error: unknown): string {
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[A-Z0-9_]{1,64}$/.test(code)) {
      return code;
    }
  }
  return "INTERNAL_ERROR";
}

export { REDACTED };
