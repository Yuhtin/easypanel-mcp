import type { ProcedureType } from "../domain/types.js";

export type ProcedureKey =
  | "update_status"
  | "inventory"
  | "inspect_project"
  | "create_project"
  | "inspect_app"
  | "create_app"
  | "destroy_app"
  | "deploy_app"
  | "start_app"
  | "stop_app"
  | "restart_app"
  | "source_image"
  | "source_git"
  | "update_env"
  | "update_resources"
  | "update_deploy"
  | "update_healthcheck"
  | "inspect_postgres"
  | "create_postgres"
  | "destroy_postgres"
  | "inspect_redis"
  | "create_redis"
  | "destroy_redis"
  | "list_domains"
  | "create_domain"
  | "delete_domain"
  | "list_actions"
  | "get_action"
  | "rotate_deploy_webhook";

interface ProcedureDefinition {
  type: ProcedureType;
  candidates: readonly string[];
  required?: boolean;
}

export const PROCEDURES: Readonly<Record<ProcedureKey, ProcedureDefinition>> = {
  update_status: { type: "query", candidates: ["update.getStatus"], required: true },
  inventory: {
    type: "query",
    candidates: ["projects.listProjectsAndServices"],
    required: true,
  },
  inspect_project: {
    type: "query",
    candidates: ["projects.inspectProject"],
    required: true,
  },
  create_project: {
    type: "mutation",
    candidates: ["projects.createProject"],
  },
  inspect_app: {
    type: "query",
    candidates: ["services.app.inspectService"],
    required: true,
  },
  create_app: {
    type: "mutation",
    candidates: ["services.app.createService"],
  },
  destroy_app: {
    type: "mutation",
    candidates: ["services.app.destroyService"],
  },
  deploy_app: {
    type: "mutation",
    candidates: ["services.app.deployService"],
  },
  start_app: {
    type: "mutation",
    candidates: ["services.app.startService"],
  },
  stop_app: {
    type: "mutation",
    candidates: ["services.app.stopService"],
  },
  restart_app: {
    type: "mutation",
    candidates: ["services.app.restartService"],
  },
  source_image: {
    type: "mutation",
    candidates: ["services.app.updateSourceImage"],
  },
  source_git: {
    type: "mutation",
    candidates: ["services.app.updateSourceGithub", "services.app.updateSourceGit"],
  },
  update_env: {
    type: "mutation",
    candidates: ["services.app.updateEnv"],
  },
  update_resources: {
    type: "mutation",
    candidates: ["services.app.updateResources"],
  },
  update_deploy: {
    type: "mutation",
    candidates: ["services.app.updateDeploy", "services.app.updateDeploySettings"],
  },
  update_healthcheck: {
    type: "mutation",
    candidates: ["services.app.updateHealthcheck", "services.app.updateHealthCheck"],
  },
  inspect_postgres: {
    type: "query",
    candidates: ["services.postgres.inspectService"],
    required: true,
  },
  create_postgres: {
    type: "mutation",
    candidates: ["services.postgres.createService"],
  },
  destroy_postgres: {
    type: "mutation",
    candidates: ["services.postgres.destroyService"],
  },
  inspect_redis: {
    type: "query",
    candidates: ["services.redis.inspectService"],
    required: true,
  },
  create_redis: {
    type: "mutation",
    candidates: ["services.redis.createService"],
  },
  destroy_redis: {
    type: "mutation",
    candidates: ["services.redis.destroyService"],
  },
  list_domains: {
    type: "query",
    candidates: ["domains.listDomains"],
    required: true,
  },
  create_domain: {
    type: "mutation",
    candidates: ["domains.createDomain"],
  },
  delete_domain: {
    type: "mutation",
    candidates: ["domains.deleteDomain"],
  },
  list_actions: {
    type: "query",
    candidates: ["actions.listActions"],
    required: true,
  },
  get_action: {
    type: "query",
    candidates: ["actions.getAction"],
    required: true,
  },
  rotate_deploy_webhook: {
    type: "mutation",
    candidates: [
      "services.app.rotateDeployWebhook",
      "services.app.regenerateDeployToken",
      "services.app.regenerateToken",
    ],
  },
};

export interface ResolvedProcedures {
  byKey: ReadonlyMap<ProcedureKey, string>;
  byName: ReadonlyMap<string, ProcedureType>;
  features: ReadonlySet<string>;
}

export function resolveProcedures(
  available: ReadonlyMap<string, ProcedureType>,
  strictRequired = true,
): ResolvedProcedures {
  const normalized = new Map<string, { name: string; type: ProcedureType }>();
  for (const [name, type] of available) {
    normalized.set(name.toLowerCase(), { name, type });
  }

  const byKey = new Map<ProcedureKey, string>();
  const byName = new Map<string, ProcedureType>();
  const features = new Set<string>();
  const missing: string[] = [];

  for (const [key, definition] of Object.entries(PROCEDURES) as [
    ProcedureKey,
    ProcedureDefinition,
  ][]) {
    const match = definition.candidates
      .map((candidate) => normalized.get(candidate.toLowerCase()))
      .find((entry) => entry?.type === definition.type);

    if (!match) {
      if (definition.required) missing.push(key);
      continue;
    }

    byKey.set(key, match.name);
    byName.set(match.name, definition.type);
    features.add(key);
  }

  if (strictRequired && missing.length > 0) {
    const error = new Error("The Easypanel capability profile is incompatible");
    Object.defineProperty(error, "code", { value: "INCOMPATIBLE_CAPABILITIES" });
    throw error;
  }

  return { byKey, byName, features };
}

export function legacy230ProcedureMap(): ReadonlyMap<string, ProcedureType> {
  const map = new Map<string, ProcedureType>();
  const knownLegacyKeys: readonly ProcedureKey[] = [
    "update_status",
    "inventory",
    "inspect_project",
    "create_project",
    "inspect_app",
    "create_app",
    "destroy_app",
    "deploy_app",
    "source_image",
    "source_git",
    "update_env",
    "update_resources",
    "inspect_postgres",
    "create_postgres",
    "destroy_postgres",
    "inspect_redis",
    "create_redis",
    "destroy_redis",
    "list_domains",
    "create_domain",
    "delete_domain",
    "list_actions",
    "get_action",
  ];
  for (const key of knownLegacyKeys) {
    const definition = PROCEDURES[key];
    map.set(definition.candidates[0] as string, definition.type);
  }
  return map;
}
