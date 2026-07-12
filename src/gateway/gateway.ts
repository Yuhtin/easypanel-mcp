import type {
  DeploySettings,
  Healthcheck,
  Resources,
  ServiceDomain,
  ServiceSource,
} from "../domain/schemas.js";
import type {
  CapabilitySnapshot,
  DeploymentSummary,
  GatewayMutationContext,
  InternalServiceSnapshot,
  Inventory,
  LifecycleActionSummary,
  LifecycleActionStatus,
  LifecycleOperation,
  ServiceKind,
} from "../domain/types.js";

export interface CreateServiceEvidence {
  databaseCredentialAccepted?: true;
}

export interface EasypanelGateway {
  discover(): Promise<CapabilitySnapshot>;
  refreshCapabilities(): Promise<CapabilitySnapshot>;
  listInventory(): Promise<Inventory>;
  inspectService(
    project: string,
    service: string,
    expectedKind?: ServiceKind,
  ): Promise<InternalServiceSnapshot>;
  listDeployments(project: string, service: string): Promise<DeploymentSummary[]>;
  getDeployment(id: string): Promise<DeploymentSummary | null>;
  getDeploymentForRequest(
    id: string,
    project: string,
    service: string,
    requestId: string,
  ): Promise<DeploymentSummary | null>;
  /** Return a complete bounded history or reject; a truncated list is unsafe. */
  listLifecycleActions(project: string, service: string): Promise<LifecycleActionSummary[]>;
  getLifecycleActionStatus(
    id: string,
    project: string,
    service: string,
    operation: LifecycleOperation,
    requestId: string,
  ): Promise<LifecycleActionStatus | null>;
  getDeployWebhookFingerprint(project: string, service: string): Promise<string | undefined>;

  createProject(project: string, context: GatewayMutationContext): Promise<void>;
  createService(
    project: string,
    service: string,
    kind: ServiceKind,
    options: { password?: string },
    context: GatewayMutationContext,
  ): Promise<CreateServiceEvidence>;
  updateSource(
    project: string,
    service: string,
    source: ServiceSource,
    context: GatewayMutationContext,
  ): Promise<void>;
  updateEnvironment(
    project: string,
    service: string,
    envDocument: string,
    context: GatewayMutationContext,
  ): Promise<void>;
  updateResources(
    project: string,
    service: string,
    resources: Resources,
    context: GatewayMutationContext,
  ): Promise<void>;
  updateDeploy(
    project: string,
    service: string,
    deploy: DeploySettings,
    context: GatewayMutationContext,
  ): Promise<void>;
  addDomain(
    project: string,
    service: string,
    domain: ServiceDomain,
    context: GatewayMutationContext,
  ): Promise<void>;
  removeDomain(
    project: string,
    service: string,
    host: string,
    context: GatewayMutationContext,
  ): Promise<void>;
  updateHealthcheck(
    project: string,
    service: string,
    healthcheck: Healthcheck | null,
    context: GatewayMutationContext,
  ): Promise<void>;
  destroyService(
    project: string,
    service: string,
    kind: ServiceKind,
    context: GatewayMutationContext,
  ): Promise<void>;
  deployService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string>;
  startService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string>;
  stopService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string>;
  restartService(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string>;
  rotateDeployWebhook(
    project: string,
    service: string,
    context: GatewayMutationContext,
  ): Promise<string>;
}
