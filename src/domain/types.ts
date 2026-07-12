import type {
  DeploySettings,
  Healthcheck,
  Resources,
  ServiceDomain,
  ServiceSource,
  ServiceSpec,
} from "./schemas.js";

export type ApiFlavor = "trpc" | "rpc" | "fake";
export type ProcedureType = "query" | "mutation";
export type ServiceKind = "app" | "postgres" | "redis";
export type Risk = "low" | "medium" | "high" | "critical";
export type ServiceRuntimeStatus = "running" | "stopped" | "deploying" | "error" | "unknown";
export type ServiceHealthStatus = "healthy" | "unhealthy" | "unknown";
export type ServiceReadiness = "ready" | "not_ready" | "unknown";
export type LifecycleOperation = "start" | "stop" | "restart";
export type LifecycleActionStatus = "pending" | "succeeded" | "failed" | "unknown";

export interface LifecycleActionSummary {
  id: string;
  project: string;
  service: string;
  operation: LifecycleOperation;
  status: LifecycleActionStatus;
}

export interface CapabilitySnapshot {
  instanceId: string;
  instanceLabel: string;
  flavor: ApiFlavor;
  version: string;
  profile: string;
  procedures: ReadonlyMap<string, ProcedureType>;
  features: ReadonlySet<string>;
}

export interface ProjectSummary {
  name: string;
}

export interface ServiceSummary {
  project: string;
  name: string;
  kind: string;
  enabled: boolean;
}

export interface Inventory {
  projects: ProjectSummary[];
  services: ServiceSummary[];
}

export interface InternalServiceSnapshot {
  exists: boolean;
  project: string;
  service: string;
  kind: ServiceKind;
  enabled: boolean;
  source?: ServiceSource;
  envDocument: string;
  resources?: Resources;
  deploy?: DeploySettings;
  domains?: ServiceDomain[];
  healthcheck?: Healthcheck | null;
  status?: ServiceRuntimeStatus;
  health?: ServiceHealthStatus;
  readiness?: ServiceReadiness;
}

export interface PublicServiceSnapshot {
  exists: boolean;
  project: string;
  service: string;
  kind: ServiceKind;
  enabled: boolean;
  source?: ServiceSource;
  environmentNames: string[];
  resources?: Resources;
  deploy?: DeploySettings;
  domains?: ServiceDomain[];
  healthcheck?: Healthcheck | null;
  status?: ServiceRuntimeStatus;
  health?: ServiceHealthStatus;
  readiness?: ServiceReadiness;
}

export interface DeploymentSummary {
  id: string;
  project: string;
  service: string;
  status: ServiceRuntimeStatus;
  createdAt?: string;
  finishedAt?: string;
}

export type PlanActionType =
  | "create_project"
  | "create_service"
  | "update_source"
  | "merge_environment"
  | "update_resources"
  | "update_deploy"
  | "add_domain"
  | "remove_domain"
  | "update_healthcheck"
  | "destroy_service"
  | "deploy_service"
  | "start_service"
  | "stop_service"
  | "restart_service"
  | "rotate_deploy_webhook";

export interface PlanAction {
  id: string;
  type: PlanActionType;
  risk: Risk;
  summary: string;
  changedFields: string[];
  details?: Record<string, unknown>;
}

export interface PublicPlan {
  planHash: string;
  target: { project: string; service: string };
  createdAt: string;
  expiresAt: string;
  actions: PlanAction[];
  noChanges: boolean;
  approval: string;
  confirmation?: string;
}

export interface StoredPlan extends PublicPlan {
  intentHash: string;
  spec?: ServiceSpec;
  operation?: "deploy" | "start" | "stop" | "restart" | "rotate_deploy_webhook";
  preconditionHash: string;
  capabilityHash: string;
  operationState?: {
    deploymentIds?: string[];
    lifecycleActions?: Array<{
      id: string;
      operation: LifecycleOperation;
      status: LifecycleActionStatus;
    }>;
    webhookFingerprint?: string;
  };
  appliedAt?: string;
  result?: ApplyResult;
}

export interface ApplyResult {
  planHash: string;
  changed: boolean;
  idempotentReplay: boolean;
  appliedActions: PlanActionType[];
  deploymentId?: string;
  actionId?: string;
  verified: boolean;
  target: { project: string; service: string };
}

export interface GatewayMutationContext {
  auditId: string;
}
