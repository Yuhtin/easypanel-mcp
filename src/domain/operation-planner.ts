import { PlanCryptography } from "../core/external-approval.js";
import type {
  InternalServiceSnapshot,
  PlanAction,
  StoredPlan,
} from "./types.js";

export type PlannedOperation = NonNullable<StoredPlan["operation"]>;

export interface OperationPlanDraft {
  planHash: string;
  intentHash: string;
  target: { project: string; service: string };
  actions: PlanAction[];
  noChanges: boolean;
  operation: PlannedOperation;
  preconditionHash: string;
  capabilityHash: string;
  operationState: NonNullable<StoredPlan["operationState"]>;
}

export function prepareOperationPlan(input: {
  operation: PlannedOperation;
  snapshot: InternalServiceSnapshot;
  state: NonNullable<StoredPlan["operationState"]>;
  features: ReadonlySet<string>;
  cryptography: PlanCryptography;
  capabilityHash: string;
}): OperationPlanDraft {
  if (!input.snapshot.exists || input.snapshot.kind !== "app") {
    const error = new Error("The target must be an existing app service");
    Object.defineProperty(error, "code", { value: "INVALID_OPERATION_TARGET" });
    throw error;
  }
  if (
    (input.operation === "start" ||
      input.operation === "stop" ||
      input.operation === "restart") &&
    input.snapshot.status !== "running" &&
    input.snapshot.status !== "stopped"
  ) {
    const error = new Error("A strict runtime state is required for lifecycle operations");
    Object.defineProperty(error, "code", { value: "INCOMPATIBLE_CAPABILITIES" });
    throw error;
  }
  if (
    input.operation === "start" ||
    input.operation === "stop" ||
    input.operation === "restart"
  ) {
    const lifecycleActions = input.state.lifecycleActions;
    if (
      lifecycleActions === undefined ||
      lifecycleActions.some(
        (action) => action.status === "pending" || action.status === "unknown",
      )
    ) {
      const error = new Error("A lifecycle action is still in progress or unknown");
      Object.defineProperty(error, "code", { value: "LIFECYCLE_ACTION_IN_PROGRESS" });
      throw error;
    }
  }
  if (
    (input.operation === "start" ||
      input.operation === "stop" ||
      input.operation === "restart") &&
    ((input.snapshot.status === "running" && !input.snapshot.enabled) ||
      (input.snapshot.status === "stopped" && input.snapshot.enabled))
  ) {
    const error = new Error("Runtime status and enabled state are inconsistent");
    Object.defineProperty(error, "code", { value: "INCOMPATIBLE_CAPABILITIES" });
    throw error;
  }

  const action: PlanAction = (() => {
    switch (input.operation) {
      case "deploy":
        return {
          id: "01-deploy_service",
          type: "deploy_service",
          risk: "high",
          summary: "Trigger one deployment for the exact app in this plan",
          changedFields: ["deployment"],
        };
      case "start":
        return {
          id: "01-start_service",
          type: "start_service",
          risk: "medium",
          summary: "Start the exact stopped app in this plan",
          changedFields: ["runtimeState"],
        };
      case "stop":
        return {
          id: "01-stop_service",
          type: "stop_service",
          risk: "critical",
          summary: "Stop the exact app in this plan and make it unavailable",
          changedFields: ["runtimeState"],
        };
      case "restart":
        return {
          id: "01-restart_service",
          type: "restart_service",
          risk: "high",
          summary: "Restart the exact app in this plan with brief unavailability",
          changedFields: ["runtimeState"],
        };
      case "rotate_deploy_webhook":
        return {
          id: "01-rotate_deploy_webhook",
          type: "rotate_deploy_webhook",
          risk: "critical",
          summary: "Rotate the deploy webhook credential without returning it",
          changedFields: ["deployWebhook"],
        };
    }
  })();
  const feature =
    input.operation === "deploy"
      ? "deploy_app"
      : input.operation === "start"
        ? "start_app"
        : input.operation === "stop"
          ? "stop_app"
          : input.operation === "restart"
            ? "restart_app"
            : "rotate_deploy_webhook";
  const noChanges =
    (input.operation === "start" &&
      input.snapshot.enabled &&
      input.snapshot.status === "running") ||
    (input.operation === "stop" &&
      !input.snapshot.enabled &&
      input.snapshot.status === "stopped");
  if (!noChanges && !input.features.has(feature)) {
    const error = new Error("The panel profile does not support this operation");
    Object.defineProperty(error, "code", { value: "FEATURE_UNSUPPORTED" });
    throw error;
  }

  const target = { project: input.snapshot.project, service: input.snapshot.service };
  const actions = noChanges ? [] : [action];
  const preconditionHash = operationPrecondition(
    input.snapshot,
    input.state,
    input.cryptography,
  );
  const material = {
    purpose: "operation-plan",
    operation: input.operation,
    target,
    actions,
    preconditionHash,
    capabilityHash: input.capabilityHash,
    state: input.state,
  };
  const intentHash = input.cryptography.signPlan(material);
  return {
    planHash: input.cryptography.createPlanHash(intentHash),
    intentHash,
    target,
    actions,
    noChanges,
    operation: input.operation,
    preconditionHash,
    capabilityHash: input.capabilityHash,
    operationState: structuredClone(input.state),
  };
}

export function operationPrecondition(
  snapshot: InternalServiceSnapshot,
  state: NonNullable<StoredPlan["operationState"]>,
  cryptography: PlanCryptography,
): string {
  return cryptography.signPlan({
    purpose: "operation-precondition",
    snapshot,
    state,
  });
}
