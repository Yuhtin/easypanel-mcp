import { z } from "zod";
import { isAbsolute, relative, resolve, sep } from "node:path";

import { ProjectNameSchema } from "./domain/schemas.js";
import {
  createHttpClientSecurityPolicy,
  type AccessMode,
  type HttpClientSecurityPolicy,
} from "./core/policy.js";

const AccessModeSchema = z.enum(["readonly", "operator", "admin"]);
const ApiFlavorSchema = z.enum(["auto", "trpc", "rpc"]);
const TransportSchema = z.enum(["stdio", "http"]);
const HttpBindHostSchema = z.enum(["127.0.0.1", "0.0.0.0", "::1", "::"]);
const InstanceLabelSchema = z
  .string()
  .min(1)
  .max(63)
  .regex(/^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/);
const SecretPrefixSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Z][A-Z0-9_]*_$/);

export interface EasypanelConfig {
  panelOrigin: string;
  tokenEnvName: "EASYPANEL_TOKEN";
  approvalKeyEnvName: "EASYPANEL_APPROVAL_KEY";
  accessMode: AccessMode;
  allowedProjects: ReadonlySet<string>;
  instanceLabel: string;
  apiFlavor: "auto" | "trpc" | "rpc";
  expectedVersion?: string;
  secretPrefix: string;
  auditPath: string;
  approvalDirectory: string;
  runtimeLockPath: string;
  webhookSinkDirectory?: string;
  approvalTtlMs: number;
  planTtlMs: number;
  timeoutMs: number;
  maxResponseBytes: number;
  actor: string;
  fakeFixture?: string;
  http: HttpClientSecurityPolicy;
  transport: "stdio" | "http";
  remoteHttp?: RemoteHttpConfig;
}

/**
 * Public-facing Streamable HTTP settings. The access token deliberately stays
 * out of this object so configuration cannot accidentally serialize it.
 */
export interface RemoteHttpConfig {
  bindHost: "127.0.0.1" | "0.0.0.0" | "::1" | "::";
  port: number;
  publicOrigin: string;
  publicHost: string;
  accessTokenEnvName: "EASYPANEL_MCP_ACCESS_TOKEN";
  maxRequestBytes: number;
  maxSessions: number;
  maxConcurrentRequests: number;
  requestDeadlineMs: number;
  sessionIdleMs: number;
  sessionMaxAgeMs: number;
}

export class ConfigError extends Error {
  readonly code = "CONFIG_INVALID";

  constructor() {
    super("CONFIG_INVALID");
    this.name = "ConfigError";
  }
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value || value.trim() === "") {
    throw new ConfigError();
  }
  return value;
}

function integer(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError();
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new ConfigError();
  }
  return value;
}

function exactHttpsOrigin(value: string): URL {
  try {
    if (value !== value.trim()) throw new ConfigError();
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      throw new ConfigError();
    }
    return url;
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError();
  }
}

function panelOrigin(value: string): string {
  return exactHttpsOrigin(value).origin;
}

function remoteAccessToken(value: string): string {
  const bytes = Buffer.byteLength(value, "utf8");
  if (
    bytes < 32 ||
    bytes > 256 ||
    !/^[A-Za-z0-9._~-]+$/.test(value)
  ) {
    throw new ConfigError();
  }
  return value;
}

/** Read and validate the separate bearer token used by the remote MCP edge. */
export function loadRemoteAccessToken(env: NodeJS.ProcessEnv = process.env): string {
  return remoteAccessToken(required(env, "EASYPANEL_MCP_ACCESS_TOKEN"));
}

function allowedProjects(value: string): ReadonlySet<string> {
  if (value.length > 8192) throw new ConfigError();
  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (entries.length === 0 || entries.length > 100 || entries.includes("*")) {
    throw new ConfigError();
  }

  const parsed = entries.map((entry) => {
    const result = ProjectNameSchema.safeParse(entry);
    if (!result.success) throw new ConfigError();
    return result.data as string;
  });

  return new Set(parsed);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): EasypanelConfig {
  if (
    env.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
    env.EASYPANEL_TLS_REJECT_UNAUTHORIZED === "0"
  ) {
    throw new ConfigError();
  }

  const modeResult = AccessModeSchema.safeParse(
    env.EASYPANEL_ACCESS_MODE?.toLowerCase() || "readonly",
  );
  const flavorResult = ApiFlavorSchema.safeParse(
    env.EASYPANEL_API_FLAVOR?.toLowerCase() || "auto",
  );
  const transportResult = TransportSchema.safeParse(
    env.EASYPANEL_MCP_TRANSPORT?.toLowerCase() || "stdio",
  );
  const labelResult = InstanceLabelSchema.safeParse(
    env.EASYPANEL_INSTANCE_LABEL || "easypanel",
  );
  const prefixResult = SecretPrefixSchema.safeParse(
    env.EASYPANEL_SECRET_PREFIX || "EASYPANEL_SECRET_",
  );
  if (
    !modeResult.success ||
    !flavorResult.success ||
    !transportResult.success ||
    !labelResult.success ||
    !prefixResult.success ||
    ["EASYPANEL_TOKEN", "EASYPANEL_APPROVAL_KEY"].some((reserved) =>
      reserved.startsWith(prefixResult.success ? prefixResult.data : ""),
    )
  ) {
    throw new ConfigError();
  }

  const fakeFixture = env.EASYPANEL_FAKE_FIXTURE?.trim() || undefined;
  if (fakeFixture && (fakeFixture.includes("\u0000") || fakeFixture.length > 4096)) {
    throw new ConfigError();
  }
  const origin = fakeFixture
    ? "https://offline-fixture.invalid"
    : panelOrigin(required(env, "EASYPANEL_URL"));
  if (!fakeFixture) required(env, "EASYPANEL_TOKEN");
  if (modeResult.data !== "readonly") {
    const approvalKey = required(env, "EASYPANEL_APPROVAL_KEY");
    const approvalKeyBytes = Buffer.byteLength(approvalKey, "utf8");
    if (
      approvalKeyBytes < 32 ||
      approvalKeyBytes > 4_096 ||
      /[\u0000-\u001f\u007f]/.test(approvalKey)
    ) {
      throw new ConfigError();
    }
  }

  const expectedVersion = env.EASYPANEL_EXPECTED_VERSION?.trim() || undefined;
  if (
    (!fakeFixture && expectedVersion === undefined) ||
    (expectedVersion !== undefined &&
      (expectedVersion.length > 96 ||
        !/^\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?$/.test(expectedVersion)))
  ) {
    throw new ConfigError();
  }

  const actor = env.EASYPANEL_AUDIT_ACTOR?.trim() || "mcp-client";
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(actor)) throw new ConfigError();

  const upstreamTimeoutMs = integer(env, "EASYPANEL_TIMEOUT_MS", 10_000, 1_000, 60_000);

  let remoteHttp: RemoteHttpConfig | undefined;
  if (transportResult.data === "http") {
    // The current approval flow deliberately keeps a symmetric signing key on
    // the local host. That is safe only for local stdio/SSH use. A remotely
    // reachable process must remain read-only until external asymmetric
    // approvals and principal-bound plans exist.
    if (modeResult.data !== "readonly") throw new ConfigError();

    const publicUrl = exactHttpsOrigin(
      required(env, "EASYPANEL_MCP_HTTP_PUBLIC_ORIGIN"),
    );
    const bindResult = HttpBindHostSchema.safeParse(
      env.EASYPANEL_MCP_HTTP_BIND_HOST || "127.0.0.1",
    );
    if (!bindResult.success) throw new ConfigError();
    loadRemoteAccessToken(env);

    // Runtime boot completes discovery before the listener starts. The remote
    // registry intentionally has no capability-refresh or planning tool, so
    // it cannot invalidate that cache. Its longest remaining path is
    // inspectService (inventory + inspection + domains), with two attempts
    // per query: six bounded upstream windows.
    if (upstreamTimeoutMs > 10_000) throw new ConfigError();
    const sessionIdleMs =
      integer(env, "EASYPANEL_MCP_HTTP_SESSION_IDLE_SECONDS", 900, 60, 3_600) *
      1_000;
    const sessionMaxAgeMs =
      integer(env, "EASYPANEL_MCP_HTTP_SESSION_MAX_AGE_SECONDS", 3_600, 300, 14_400) *
      1_000;
    if (sessionMaxAgeMs < sessionIdleMs) throw new ConfigError();

    const remoteConfig: RemoteHttpConfig = Object.freeze({
      bindHost: bindResult.data,
      port: integer(env, "EASYPANEL_MCP_HTTP_PORT", 3_000, 1_024, 65_535),
      publicOrigin: publicUrl.origin,
      publicHost: publicUrl.host,
      accessTokenEnvName: "EASYPANEL_MCP_ACCESS_TOKEN",
      maxRequestBytes: integer(
        env,
        "EASYPANEL_MCP_HTTP_MAX_REQUEST_BYTES",
        131_072,
        1_024,
        131_072,
      ),
      maxSessions: integer(env, "EASYPANEL_MCP_HTTP_MAX_SESSIONS", 16, 1, 64),
      maxConcurrentRequests: integer(
        env,
        "EASYPANEL_MCP_HTTP_MAX_CONCURRENT_REQUESTS",
        16,
        1,
        64,
      ),
      requestDeadlineMs: integer(
        env,
        "EASYPANEL_MCP_HTTP_REQUEST_TIMEOUT_MS",
        70_000,
        11_000,
        90_000,
      ),
      sessionIdleMs,
      sessionMaxAgeMs,
    });
    if (remoteConfig.requestDeadlineMs < upstreamTimeoutMs * 6 + 5_000) {
      throw new ConfigError();
    }
    remoteHttp = remoteConfig;
  }

  const auditPath = env.EASYPANEL_AUDIT_PATH || ".state/audit.jsonl";
  const approvalDirectory = env.EASYPANEL_APPROVAL_DIR || ".state/approvals";
  const runtimeLockPath = env.EASYPANEL_RUNTIME_LOCK_PATH || ".state/runtime.lock";
  const webhookSinkDirectory = env.EASYPANEL_WEBHOOK_SINK_DIR?.trim() || undefined;
  const localFiles = [
    resolve(auditPath),
    resolve(runtimeLockPath),
    ...(fakeFixture ? [resolve(fakeFixture)] : []),
  ];
  const localDirectories = [
    resolve(approvalDirectory),
    ...(webhookSinkDirectory ? [resolve(webhookSinkDirectory)] : []),
  ];
  if (
    auditPath.includes("\u0000") ||
    auditPath.trim() === "" ||
    auditPath.length > 4096 ||
    approvalDirectory.includes("\u0000") ||
    approvalDirectory.trim() === "" ||
    approvalDirectory.length > 4096 ||
    runtimeLockPath.includes("\u0000") ||
    runtimeLockPath.trim() === "" ||
    runtimeLockPath.length > 4096 ||
    (webhookSinkDirectory !== undefined &&
      (webhookSinkDirectory.includes("\u0000") ||
        webhookSinkDirectory.length > 4096)) ||
    localFiles.some((file, index) =>
      localFiles.slice(index + 1).some((other) => directoriesOverlap(file, other)),
    ) ||
    localDirectories.some((directory, index) =>
      localDirectories.slice(index + 1).some((other) => directoriesOverlap(directory, other)),
    ) ||
    localFiles.some((file) =>
      localDirectories.some((directory) => directoriesOverlap(file, directory)),
    )
  ) {
    throw new ConfigError();
  }

  return Object.freeze({
    panelOrigin: origin,
    tokenEnvName: "EASYPANEL_TOKEN",
    approvalKeyEnvName: "EASYPANEL_APPROVAL_KEY",
    accessMode: modeResult.data,
    allowedProjects: allowedProjects(required(env, "EASYPANEL_ALLOWED_PROJECTS")),
    instanceLabel: labelResult.data,
    apiFlavor: flavorResult.data,
    expectedVersion,
    secretPrefix: prefixResult.data,
    auditPath,
    approvalDirectory,
    runtimeLockPath,
    webhookSinkDirectory,
    approvalTtlMs:
      integer(env, "EASYPANEL_APPROVAL_TTL_SECONDS", 300, 30, 900) * 1000,
    planTtlMs:
      integer(env, "EASYPANEL_PLAN_TTL_SECONDS", 900, 30, 3600) * 1000,
    timeoutMs: upstreamTimeoutMs,
    maxResponseBytes: integer(
      env,
      "EASYPANEL_MAX_RESPONSE_BYTES",
      2_097_152,
      1024,
      10_485_760,
    ),
    actor,
    fakeFixture,
    http: createHttpClientSecurityPolicy(origin),
    transport: transportResult.data,
    ...(remoteHttp ? { remoteHttp } : {}),
  });
}

function directoriesOverlap(left: string, right: string): boolean {
  return pathIsInside(left, right) || pathIsInside(right, left);
}

function pathIsInside(directory: string, candidate: string): boolean {
  const path = relative(resolve(directory), resolve(candidate));
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
