import { canonicalJson, compareCodePoints } from "../core/canonical-json.js";
import { PlanCryptography } from "../core/external-approval.js";
import type { SecretProvider } from "../secrets/env-secret-provider.js";
import { EnvDocument } from "./env-document.js";
import type { ServiceSpec } from "./schemas.js";
import type {
  InternalServiceSnapshot,
  PlanAction,
  PlanActionType,
  PublicServiceSnapshot,
} from "./types.js";

export interface ServicePlanDraft {
  planHash: string;
  intentHash: string;
  target: { project: string; service: string };
  actions: PlanAction[];
  noChanges: boolean;
  spec: ServiceSpec;
  preconditionHash: string;
  capabilityHash: string;
}

export interface PreparePlanInput {
  spec: ServiceSpec;
  projectExists: boolean;
  snapshot: InternalServiceSnapshot;
  features: ReadonlySet<string>;
  secrets: Pick<SecretProvider, "resolve">;
  cryptography: PlanCryptography;
  capabilityHash: string;
  /** Resolve references only after external approval, during apply/verify. */
  resolveSecretValues?: boolean;
}

export function prepareServicePlan(input: PreparePlanInput): ServicePlanDraft {
  const { spec, snapshot } = input;
  const actions: PlanAction[] = [];
  const add = (
    type: PlanActionType,
    risk: PlanAction["risk"],
    summary: string,
    changedFields: string[],
    feature: string = type,
    details?: Record<string, unknown>,
  ): void => {
    assertFeature(input.features, feature);
    actions.push({
      id: `${String(actions.length + 1).padStart(2, "0")}-${type}`,
      type,
      risk,
      summary,
      changedFields: [...changedFields].sort(),
      ...(details ? { details: structuredClone(details) } : {}),
    });
  };

  if (spec.ensure === "absent") {
    if (snapshot.exists) {
      add(
        "destroy_service",
        "critical",
        "Permanently destroy the exact service in this plan",
        ["service"],
        destroyFeature(spec.kind),
      );
    }
    return finishDraft(input, actions);
  }

  if (!input.projectExists) {
    add("create_project", "medium", "Create the allowlisted project", ["project"]);
  }
  if (!snapshot.exists) {
    if (spec.kind !== "app" && spec.database === undefined) {
      throw codedError(
        "DATABASE_BOOTSTRAP_REQUIRED",
        "Database creation requires an explicit secret reference",
      );
    }
    add(
      "create_service",
      "medium",
      `Create a ${spec.kind} service`,
      ["kind", "service"],
      createFeature(spec.kind),
      {
        kind: spec.kind,
        ...(spec.database
          ? { referenceNames: [spec.database.initialPassword.name] }
          : {}),
      },
    );
  }

  if (spec.kind !== "app") {
    if (
      snapshot.exists &&
      spec.database !== undefined &&
      !input.resolveSecretValues
    ) {
      throw codedError(
        "DATABASE_BOOTSTRAP_CREATION_ONLY",
        "An initial database credential is valid only while creating the service",
      );
    }
    return finishDraft(input, actions);
  }

  if (spec.source && canonicalJson(spec.source) !== canonicalJson(snapshot.source)) {
    add(
      "update_source",
      "high",
      "Replace the application source configuration",
      ["source"],
      spec.source.type === "image" ? "source_image" : "source_git",
      { source: spec.source },
    );
  }

  if (spec.environment) {
    const desired = EnvDocument.parse(snapshot.exists ? snapshot.envDocument : "");
    const changedNames = new Set<string>();
    for (const [name, assignment] of Object.entries(spec.environment.merge).sort(([a], [b]) =>
      compareCodePoints(a, b),
    )) {
      if (assignment.from === "secret") {
        // Planning may run in readonly mode. Resolving here would expose a
        // secret-name existence oracle before a human approved the operation.
        if (!input.resolveSecretValues) {
          changedNames.add(name);
          continue;
        }
        const value = input.secrets.resolve(assignment.name);
        if (desired.get(name) !== value) {
          desired.set(name, value);
          changedNames.add(name);
        }
        continue;
      }
      const value = assignment.value;
      if (desired.get(name) !== value) {
        desired.set(name, value);
        changedNames.add(name);
      }
    }
    for (const name of spec.environment.remove) {
      if (desired.remove(name)) changedNames.add(name);
    }
    if (changedNames.size > 0) {
      add(
        "merge_environment",
        "high",
        "Merge environment keys while preserving all unspecified variables",
        [...changedNames].map((name) => `environment.${name}`),
        "update_env",
        {
          setNames: Object.keys(spec.environment.merge).sort(),
          removeNames: [...spec.environment.remove].sort(),
          secretRefs: Object.values(spec.environment.merge)
            .filter((assignment) => assignment.from === "secret")
            .map((assignment) => assignment.name)
            .sort(),
        },
      );
    }
  }

  if (spec.resources && canonicalJson(spec.resources) !== canonicalJson(snapshot.resources)) {
    add(
      "update_resources",
      "medium",
      "Update the complete CPU and memory resource set",
      ["resources"],
      "update_resources",
      { resources: spec.resources },
    );
  }

  if (spec.deploy && canonicalJson(spec.deploy) !== canonicalJson(snapshot.deploy)) {
    add(
      "update_deploy",
      "medium",
      "Update replica and deploy settings",
      ["deploy"],
      "update_deploy",
      { deploy: spec.deploy },
    );
  }

  if (spec.domains) {
    const current = new Map((snapshot.domains ?? []).map((domain) => [domain.host, domain]));
    const desired = new Map(spec.domains.map((domain) => [domain.host, domain]));
    for (const [host, domain] of [...desired].sort(([a], [b]) => compareCodePoints(a, b))) {
      if (canonicalJson(current.get(host)) !== canonicalJson(domain)) {
        if (current.has(host)) {
          add(
            "remove_domain",
            "high",
            "Remove a domain whose routing configuration will be replaced",
            [`domains.${host}`],
            "delete_domain",
            { host },
          );
        }
        add(
          "add_domain",
          "medium",
          "Add an HTTPS domain routing entry",
          [`domains.${host}`],
          "create_domain",
          { domain },
        );
      }
    }
    for (const host of [...current.keys()].sort()) {
      if (!desired.has(host)) {
        add(
          "remove_domain",
          "high",
          "Remove a domain that is absent from desired state",
          [`domains.${host}`],
          "delete_domain",
          { host },
        );
      }
    }
  }

  if (
    spec.healthcheck !== undefined &&
    canonicalJson(spec.healthcheck) !== canonicalJson(snapshot.healthcheck)
  ) {
    add(
      "update_healthcheck",
      "medium",
      "Update the application healthcheck",
      ["healthcheck"],
      "update_healthcheck",
      { healthcheck: spec.healthcheck ?? null },
    );
  }

  return finishDraft(input, actions);
}

export function publicSnapshot(snapshot: InternalServiceSnapshot): PublicServiceSnapshot {
  return {
    exists: snapshot.exists,
    project: snapshot.project,
    service: snapshot.service,
    kind: snapshot.kind,
    enabled: snapshot.enabled,
    source: snapshot.source,
    environmentNames: EnvDocument.parse(snapshot.envDocument).names(),
    resources: snapshot.resources,
    deploy: snapshot.deploy,
    domains: snapshot.domains,
    healthcheck: snapshot.healthcheck,
    status: snapshot.status,
    health: snapshot.health,
    readiness: snapshot.readiness,
  };
}

function codedError(code: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, "code", { value: code });
  return error;
}

export function snapshotPrecondition(
  projectExists: boolean,
  snapshot: InternalServiceSnapshot,
  cryptography: PlanCryptography,
): string {
  return cryptography.signPlan({
    purpose: "precondition",
    projectExists,
    snapshot,
  });
}

function finishDraft(
  input: PreparePlanInput,
  actions: PlanAction[],
): ServicePlanDraft {
  const preconditionHash = snapshotPrecondition(
    input.projectExists,
    input.snapshot,
    input.cryptography,
  );
  const material = {
    purpose: "service-plan",
    target: { project: input.spec.project, service: input.spec.service },
    spec: input.spec,
    actions,
    preconditionHash,
    capabilityHash: input.capabilityHash,
  };
  const intentHash = input.cryptography.signPlan(material);
  return {
    planHash: input.cryptography.createPlanHash(intentHash),
    intentHash,
    target: material.target,
    actions,
    noChanges: actions.length === 0,
    spec: structuredClone(input.spec),
    preconditionHash,
    capabilityHash: input.capabilityHash,
  };
}

function assertFeature(features: ReadonlySet<string>, feature: string): void {
  if (!features.has(feature)) {
    const error = new Error("The connected Easypanel profile does not support the planned action");
    Object.defineProperty(error, "code", { value: "FEATURE_UNSUPPORTED" });
    throw error;
  }
}

function createFeature(kind: ServiceSpec["kind"]): string {
  return kind === "app" ? "create_app" : kind === "postgres" ? "create_postgres" : "create_redis";
}

function destroyFeature(kind: ServiceSpec["kind"]): string {
  return kind === "app" ? "destroy_app" : kind === "postgres" ? "destroy_postgres" : "destroy_redis";
}
