import { SecretRegistry } from "../core/redaction.js";
import { SecretNameSchema } from "../domain/schemas.js";

export interface SecretProvider {
  getPanelToken(): string;
  getApprovalKey(): string;
  resolve(name: string): string;
}

export interface EnvSecretProviderOptions {
  env?: NodeJS.ProcessEnv;
  prefix?: string;
  registry?: SecretRegistry;
}

export class SecretProviderError extends Error {
  readonly code: "SECRET_INVALID" | "SECRET_NOT_FOUND";

  constructor(code: "SECRET_INVALID" | "SECRET_NOT_FOUND") {
    super(code);
    this.name = "SecretProviderError";
    this.code = code;
  }
}

export class EnvSecretProvider implements SecretProvider {
  readonly #env: NodeJS.ProcessEnv;
  readonly #prefix: string;
  readonly #registry: SecretRegistry;

  constructor(options: EnvSecretProviderOptions = {}) {
    this.#env = options.env ?? process.env;
    this.#prefix = options.prefix ?? "EASYPANEL_SECRET_";
    this.#registry = options.registry ?? new SecretRegistry();

    if (
      !/^[A-Z][A-Z0-9_]*_$/.test(this.#prefix) ||
      ["EASYPANEL_TOKEN", "EASYPANEL_APPROVAL_KEY"].some((reserved) =>
        reserved.startsWith(this.#prefix),
      )
    ) {
      throw new SecretProviderError("SECRET_INVALID");
    }
  }

  get registry(): SecretRegistry {
    return this.#registry;
  }

  getPanelToken(): string {
    return this.#read("EASYPANEL_TOKEN", 16, 8_192, /\s|[\u0000-\u001f\u007f]/);
  }

  getApprovalKey(): string {
    return this.#read("EASYPANEL_APPROVAL_KEY", 32, 4_096, /[\u0000-\u001f\u007f]/);
  }

  resolve(name: string): string {
    const parsed = SecretNameSchema.safeParse(name);
    if (!parsed.success) {
      throw new SecretProviderError("SECRET_INVALID");
    }
    return this.#read(`${this.#prefix}${parsed.data}`, 8, 8_192);
  }

  #read(
    envName: string,
    minimumBytes: number,
    maximumBytes: number,
    forbidden?: RegExp,
  ): string {
    if (!Object.prototype.hasOwnProperty.call(this.#env, envName)) {
      throw new SecretProviderError("SECRET_NOT_FOUND");
    }
    const value = this.#env[envName];
    if (!value) {
      throw new SecretProviderError("SECRET_NOT_FOUND");
    }
    const bytes = Buffer.byteLength(value, "utf8");
    if (
      bytes < minimumBytes ||
      bytes > maximumBytes ||
      value.includes("\u0000") ||
      forbidden?.test(value)
    ) {
      throw new SecretProviderError("SECRET_INVALID");
    }
    this.#registry.add(value);
    return value;
  }
}
