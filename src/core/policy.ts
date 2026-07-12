import type { PlanActionType, Risk } from "../domain/types.js";
import { CRITICAL_ACTION_TYPES, isCriticalAction } from "./risk.js";

export type AccessMode = "readonly" | "operator" | "admin";

export interface HttpClientSecurityPolicy {
  readonly origin: string;
  readonly requireHttps: true;
  readonly redirect: "error";
  readonly rejectUnauthorized: true;
}

export interface PolicyOptions {
  accessMode?: AccessMode;
  allowedProjects: Iterable<string>;
  http: HttpClientSecurityPolicy;
}

export interface PolicyRequest {
  project: string;
  operation: "query" | "mutation";
  action?: PlanActionType;
  risk?: Risk;
}

export interface PolicyDecision {
  allowed: boolean;
  code: "ALLOWED" | "PROJECT_DENIED" | "READONLY" | "ADMIN_REQUIRED" | "ACTION_DENIED";
}

const OPERATOR_ACTIONS = new Set<PlanActionType>([
  "create_project",
  "create_service",
  "update_source",
  "merge_environment",
  "update_resources",
  "update_deploy",
  "add_domain",
  "remove_domain",
  "update_healthcheck",
  "deploy_service",
  "start_service",
  "restart_service",
]);

const ADMIN_ACTIONS = new Set<PlanActionType>([
  ...OPERATOR_ACTIONS,
  ...CRITICAL_ACTION_TYPES,
]);
const PROJECT = /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/;

export class PolicyError extends Error {
  readonly code: PolicyDecision["code"];

  constructor(code: PolicyDecision["code"]) {
    super(code);
    this.name = "PolicyError";
    this.code = code;
  }
}

export function createHttpClientSecurityPolicy(origin: string): HttpClientSecurityPolicy {
  const parsed = new URL(origin);
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new PolicyError("ACTION_DENIED");
  }

  return Object.freeze({
    origin: parsed.origin,
    requireHttps: true,
    redirect: "error",
    rejectUnauthorized: true,
  });
}

export class PolicyEngine {
  readonly accessMode: AccessMode;
  readonly http: HttpClientSecurityPolicy;
  readonly #allowedProjects: ReadonlySet<string>;

  constructor(options: PolicyOptions) {
    this.accessMode = options.accessMode ?? "readonly";
    const projects = [...options.allowedProjects];
    if (
      projects.length === 0 ||
      projects.some((project) => project === "*" || !PROJECT.test(project))
    ) {
      throw new PolicyError("PROJECT_DENIED");
    }

    this.#allowedProjects = new Set(projects);
    this.http = options.http;
  }

  get allowedProjects(): readonly string[] {
    return [...this.#allowedProjects].sort();
  }

  evaluate(request: PolicyRequest): PolicyDecision {
    if (!this.#allowedProjects.has(request.project)) {
      return { allowed: false, code: "PROJECT_DENIED" };
    }

    if (request.operation === "query") {
      return { allowed: true, code: "ALLOWED" };
    }

    if (this.accessMode === "readonly") {
      return { allowed: false, code: "READONLY" };
    }

    if (!request.action) {
      return { allowed: false, code: "ACTION_DENIED" };
    }

    if (!ADMIN_ACTIONS.has(request.action)) {
      return { allowed: false, code: "ACTION_DENIED" };
    }

    if (
      isCriticalAction(request.action, request.risk)
    ) {
      return this.accessMode === "admin"
        ? { allowed: true, code: "ALLOWED" }
        : { allowed: false, code: "ADMIN_REQUIRED" };
    }

    if (this.accessMode === "operator" && !OPERATOR_ACTIONS.has(request.action)) {
      return { allowed: false, code: "ACTION_DENIED" };
    }

    return { allowed: true, code: "ALLOWED" };
  }

  assertAllowed(request: PolicyRequest): void {
    const decision = this.evaluate(request);
    if (!decision.allowed) {
      throw new PolicyError(decision.code);
    }
  }

  assertRequestUrl(value: string | URL): URL {
    const url = value instanceof URL ? new URL(value) : new URL(value);
    if (
      url.protocol !== "https:" ||
      url.origin !== this.http.origin ||
      url.username !== "" ||
      url.password !== ""
    ) {
      throw new PolicyError("ACTION_DENIED");
    }
    return url;
  }
}
