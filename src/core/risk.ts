import type { PlanAction, PlanActionType, Risk } from "../domain/types.js";

export const CRITICAL_ACTION_TYPES: readonly PlanActionType[] = Object.freeze([
  "destroy_service",
  "rotate_deploy_webhook",
  "stop_service",
]);

const CRITICAL_ACTION_SET = new Set(CRITICAL_ACTION_TYPES);

export function isCriticalAction(
  action: PlanActionType,
  risk?: Risk,
): boolean {
  return risk === "critical" || CRITICAL_ACTION_SET.has(action);
}

export function isCriticalPlan(
  plan: Pick<{ actions: PlanAction[] }, "actions">,
): boolean {
  return plan.actions.some((action) => isCriticalAction(action.type, action.risk));
}
