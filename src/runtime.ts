import { randomBytes, timingSafeEqual } from "node:crypto";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  type EasypanelConfig,
  loadConfig,
  loadRemoteAccessToken,
} from "./config.js";
import { AdmissionGate } from "./core/admission-gate.js";
import { JsonlAuditLog } from "./core/audit.js";
import {
  ExternalApprovalStore,
  PlanCryptography,
} from "./core/external-approval.js";
import { PlanStore } from "./core/plan-store.js";
import { PolicyEngine } from "./core/policy.js";
import { SecretRegistry } from "./core/redaction.js";
import { SingleInstanceLock } from "./core/single-instance.js";
import { EasypanelOperator } from "./domain/operator.js";
import { FakeEasypanelGateway } from "./gateway/fake-gateway.js";
import type { EasypanelGateway } from "./gateway/gateway.js";
import { HttpEasypanelGateway } from "./gateway/http-gateway.js";
import { EnvSecretProvider } from "./secrets/env-secret-provider.js";
import { FileWebhookSecretSink } from "./secrets/webhook-secret-sink.js";
import { createEasypanelMcpServer } from "./server.js";

export interface ConfiguredRuntime {
  readonly config: EasypanelConfig;
  /** Creates an MCP protocol instance backed by the one shared, guarded runtime. */
  createMcpServer(): McpServer;
  /**
   * Verify the separate remote bearer against the exact startup environment.
   * The token itself never crosses the runtime boundary or configuration object.
   */
  verifyRemoteAccessToken(candidate: string): boolean;
  /** Releases the singleton lock during an intentional graceful shutdown. */
  close(): Promise<void>;
}

/**
 * Build all sensitive state once. HTTP creates a protocol server per session;
 * gateway, plan store, operator locks, redaction base and admission gate must
 * instead stay process-global.
 */
export async function createConfiguredRuntime(
  env: NodeJS.ProcessEnv = process.env,
): Promise<ConfiguredRuntime> {
  const config = loadConfig(env);
  const registry = new SecretRegistry();
  const secrets = new EnvSecretProvider({
    env,
    prefix: config.secretPrefix,
    registry,
  });
  const remoteAccessToken =
    config.remoteHttp !== undefined ? loadRemoteAccessToken(env) : undefined;
  const remoteAccessTokenBytes =
    remoteAccessToken !== undefined ? Buffer.from(remoteAccessToken, "utf8") : undefined;
  if (remoteAccessToken !== undefined) {
    // The bearer credential is an edge secret too. Registering it before the
    // base seals ensures accidental reflection is redacted by every tool call.
    registry.add(remoteAccessToken);
  }

  const approvalKey =
    config.accessMode === "readonly" && !env[config.approvalKeyEnvName]
      ? randomBytes(32).toString("hex")
      : secrets.getApprovalKey();
  registry.add(approvalKey);
  const cryptography = new PlanCryptography(approvalKey);
  const approvals = new ExternalApprovalStore({
    directory: config.approvalDirectory,
    key: approvalKey,
    ttlMs: config.approvalTtlMs,
  });
  const policy = new PolicyEngine({
    accessMode: config.accessMode,
    allowedProjects: config.allowedProjects,
    http: config.http,
  });
  const audit = new JsonlAuditLog({
    path: config.auditPath,
  });
  const plans = new PlanStore({ ttlMs: config.planTtlMs });

  let gateway: EasypanelGateway;
  if (config.fakeFixture !== undefined) {
    gateway = await FakeEasypanelGateway.fromFile(config.fakeFixture, registry);
  } else {
    gateway = new HttpEasypanelGateway({
      baseUrl: new URL(config.panelOrigin),
      token: secrets.getPanelToken(),
      instanceLabel: config.instanceLabel,
      apiFlavor: config.apiFlavor,
      expectedVersion: config.expectedVersion!,
      timeoutMs: config.timeoutMs,
      maxResponseBytes: config.maxResponseBytes,
      secrets: registry,
    });
  }

  const operator = new EasypanelOperator({
    gateway,
    policy,
    plans,
    approvals,
    cryptography,
    secrets,
    ...(config.webhookSinkDirectory
      ? { webhookSink: new FileWebhookSecretSink(config.webhookSinkDirectory) }
      : {}),
    audit,
    actor: config.actor,
  });

  registry.sealBase();
  const capabilities = await registry.runScoped(() => operator.capabilities());
  if (
    config.expectedVersion !== undefined &&
    capabilities.version !== config.expectedVersion
  ) {
    throw codedBootFailure();
  }

  let lock: SingleInstanceLock | undefined;
  // A remote listener always needs singleton state even in readonly mode: its
  // session and plan stores are deliberately local and must not split across
  // replicas. The template mounts the state volume and runs one replica.
  if (
    config.fakeFixture === undefined &&
    (config.accessMode !== "readonly" || config.transport === "http")
  ) {
    lock = await SingleInstanceLock.acquire(config.runtimeLockPath);
  }

  const admission = new AdmissionGate(
    config.remoteHttp?.maxConcurrentRequests ?? 16,
  );
  let closed = false;

  return Object.freeze({
    config,
    createMcpServer(): McpServer {
      if (closed) throw codedBootFailure();
      return createEasypanelMcpServer(operator, registry, { admission });
    },
    verifyRemoteAccessToken(candidate: string): boolean {
      if (remoteAccessTokenBytes === undefined) return false;
      const actual = Buffer.from(candidate, "utf8");
      const sameLength = remoteAccessTokenBytes.length === actual.length;
      const comparable = sameLength ? actual : remoteAccessTokenBytes;
      return timingSafeEqual(remoteAccessTokenBytes, comparable) && sameLength;
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      if (lock !== undefined) await lock.release();
    },
  });
}

function codedBootFailure(): Error {
  const error = new Error("BOOT_FAILED");
  Object.defineProperty(error, "code", { value: "INCOMPATIBLE_CAPABILITIES" });
  return error;
}
