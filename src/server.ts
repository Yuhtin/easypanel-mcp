import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { AdmissionGate } from "./core/admission-gate.js";
import { disabledJsonSchemaValidator } from "./core/disabled-json-schema-validator.js";
import { currentInvocationAbort } from "./core/invocation-abort.js";
import { redactStructure, safeErrorCode, SecretRegistry } from "./core/redaction.js";
import type { EasypanelOperator } from "./domain/operator.js";
import {
  ApplyInputSchema,
  PlannedOperationInputSchema,
  ProjectNameSchema,
  ServiceSpecSchema,
  TargetSchema,
} from "./domain/schemas.js";

const EmptyInputSchema = z.object({}).strict();
const ProjectInputSchema = z.object({ project: ProjectNameSchema }).strict();
const TargetInputSchema = TargetSchema.strict();
const ApplyServiceInputSchema = ApplyInputSchema.strict();
const PlannedOperationToolInputSchema = PlannedOperationInputSchema.strict();
const PlannedLifecycleInputSchema = TargetSchema.extend({
  operation: z.enum(["start", "stop", "restart"]),
  planHash: z.string().length(64).regex(/^[a-f0-9]+$/).optional(),
}).strict();
// Keep an object schema here so the MCP SDK can publish its JSON Schema. The
// operator applies ServiceSpecSchema's cross-field refinements again in the
// handler before any planning work.
const ServiceSpecInputSchema = ServiceSpecSchema.innerType()
  .extend({ ensure: z.literal("present").default("present") })
  .strict();
const DeploymentStatusInputSchema = TargetSchema.extend({
  id: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
}).strict();
const SanitizedLogsInputSchema = TargetSchema.extend({
  maxLines: z.number().int().min(1).max(500).default(200),
}).strict();

const PUBLIC_ERROR_CODES = new Set([
  "ACTION_DENIED",
  "ADMIN_REQUIRED",
  "AUDIT_WRITE_FAILED",
  "CONFIG_INVALID",
  "INCOMPATIBLE_CAPABILITIES",
  "INTERNAL_ERROR",
  "OUTPUT_VALIDATION_FAILED",
  "PLAN_APPROVAL_INVALID",
  "PLAN_CONFIRMATION_REQUIRED",
  "PLAN_EXPIRED",
  "PLAN_IN_PROGRESS",
  "PLAN_CAPACITY",
  "PLAN_INVALID",
  "PLAN_NOT_FOUND",
  "PLAN_UNCERTAIN",
  "PRECONDITION_FAILED",
  "PROJECT_DENIED",
  "READONLY",
  "SERVER_BUSY",
  "SECRET_INVALID",
  "SECRET_NOT_FOUND",
  "SECRET_SINK_FAILED",
  "UPSTREAM_ERROR",
  "UPSTREAM_RESPONSE_TOO_LARGE",
  "UPSTREAM_TIMEOUT",
  "VERIFY_FAILED",
]);

const ERROR_CODE_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  APPROVAL_CONFIGURATION_INVALID: "PLAN_APPROVAL_INVALID",
  APPROVAL_EXPIRED: "PLAN_APPROVAL_INVALID",
  APPROVAL_INVALID: "PLAN_APPROVAL_INVALID",
  APPROVAL_IO_FAILED: "PLAN_APPROVAL_INVALID",
  APPROVAL_REQUIRED: "PLAN_APPROVAL_INVALID",
  CONFIRMATION_REQUIRED: "PLAN_CONFIRMATION_REQUIRED",
  AUDIT_EVENT_INVALID: "INTERNAL_ERROR",
  DATABASE_BOOTSTRAP_CREATION_ONLY: "PLAN_INVALID",
  DATABASE_BOOTSTRAP_REQUIRED: "PLAN_INVALID",
  FEATURE_UNSUPPORTED: "INCOMPATIBLE_CAPABILITIES",
  INCOMPATIBLE_API: "INCOMPATIBLE_CAPABILITIES",
  INCOMPATIBLE_VERSION: "INCOMPATIBLE_CAPABILITIES",
  INVALID_CONFIGURATION: "CONFIG_INVALID",
  INVALID_INPUT: "PLAN_INVALID",
  INVALID_FIXTURE: "CONFIG_INVALID",
  INVALID_INSTANCE_URL: "CONFIG_INVALID",
  INVALID_OPERATION_TARGET: "ACTION_DENIED",
  INVALID_UPSTREAM_RESPONSE: "UPSTREAM_ERROR",
  INVENTORY_INCONSISTENT: "UPSTREAM_ERROR",
  LIFECYCLE_ACTION_IN_PROGRESS: "ACTION_DENIED",
  INSTANCE_ALREADY_RUNNING: "CONFIG_INVALID",
  INSTANCE_LOCK_FAILED: "CONFIG_INVALID",
  ORIGIN_VIOLATION: "CONFIG_INVALID",
  PLAN_HASH_CONFLICT: "PLAN_INVALID",
  PLAN_NOT_CLAIMED: "PLAN_INVALID",
  PLAN_RESULT_INVALID: "PLAN_INVALID",
  PLAN_TARGET_MISMATCH: "PLAN_INVALID",
  PRECONDITION_CHANGED: "PRECONDITION_FAILED",
  PROCEDURE_BLOCKED: "INCOMPATIBLE_CAPABILITIES",
  PROJECT_NOT_FOUND: "ACTION_DENIED",
  RESPONSE_TOO_LARGE: "UPSTREAM_RESPONSE_TOO_LARGE",
  REDACTION_CAPACITY_EXCEEDED: "OUTPUT_VALIDATION_FAILED",
  SECRET_CHANGED: "PRECONDITION_FAILED",
  SERVICE_KIND_MISMATCH: "ACTION_DENIED",
  SERVICE_NOT_FOUND: "ACTION_DENIED",
  TLS_VALIDATION_DISABLED: "CONFIG_INVALID",
  UNSUPPORTED_DOMAIN_SHAPE: "INCOMPATIBLE_CAPABILITIES",
  UNSUPPORTED_SERVICE_SOURCE: "INCOMPATIBLE_CAPABILITIES",
  UNSUPPORTED_SERVICE_KIND: "ACTION_DENIED",
  UPSTREAM_REJECTED: "UPSTREAM_ERROR",
  UPSTREAM_TARGET_MISMATCH: "UPSTREAM_ERROR",
  UPSTREAM_UNAVAILABLE: "UPSTREAM_ERROR",
  VERSION_MISMATCH: "INCOMPATIBLE_CAPABILITIES",
});

export function createEasypanelMcpServer(
  operator: EasypanelOperator,
  secrets: SecretRegistry,
  options: { admission?: AdmissionGate } = {},
): McpServer {
  // The only values allowed to survive across tool calls are those registered
  // deliberately during bootstrap. Runtime additions must belong to an
  // AsyncLocalStorage-backed invocation scope.
  secrets.sealBase();
  const server = new McpServer(
    {
      name: "easypanel-mcp",
      version: "0.1.0",
    },
    {
      instructions:
        "Operate only through the declared Easypanel tools. Mutations require a fresh plan and an external human approval; a plan response is not approval. Deployment-log content is disabled by policy.",
      jsonSchemaValidator: disabledJsonSchemaValidator,
    },
  );
  // A remote HTTP runtime creates one McpServer per authenticated session.
  // Its gate is injected so sessions cannot multiply the process-wide tool
  // concurrency budget. Stdio retains the same bounded default.
  const admission = options.admission ?? new AdmissionGate(16);

  const invoke = async (operation: () => Promise<unknown>): Promise<CallToolResult> => {
    const invocationSignal = currentInvocationAbort();
    if (invocationSignal?.aborted) return errorResult("UPSTREAM_TIMEOUT");
    const release = (() => {
      try {
        return admission.enter();
      } catch {
        return undefined;
      }
    })();
    if (!release) return errorResult("SERVER_BUSY");
    try {
      return await secrets.runScoped<CallToolResult>(async () => {
        if (invocationSignal?.aborted) return errorResult("UPSTREAM_TIMEOUT");
        try {
          const output = await operation();
          if (invocationSignal?.aborted) return errorResult("UPSTREAM_TIMEOUT");
          const projected = redactStructure(output, secrets);
          const serialized = JSON.stringify(projected);
          if (
            serialized === undefined ||
            Buffer.byteLength(serialized, "utf8") > 2_097_152
          ) {
            return errorResult("OUTPUT_VALIDATION_FAILED");
          }
          return {
            content: [{ type: "text", text: serialized }],
          };
        } catch (error: unknown) {
          return errorResult(publicErrorCode(error));
        }
      });
    } finally {
      release();
    }
  };

  server.registerTool(
    "easypanel_capabilities",
    {
      description:
        "Return the sanitized Easypanel compatibility profile, logical features, access mode, and project allowlist.",
      inputSchema: EmptyInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async () => invoke(() => operator.capabilities()),
  );

  server.registerTool(
    "easypanel_list_projects",
    {
      description: "List only projects in the configured Easypanel project allowlist.",
      inputSchema: EmptyInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async () => invoke(() => operator.listProjects()),
  );

  server.registerTool(
    "easypanel_list_services",
    {
      description: "List sanitized service summaries for one allowlisted project.",
      inputSchema: ProjectInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ project }) => invoke(() => operator.listServices(project)),
  );

  server.registerTool(
    "easypanel_inspect_service",
    {
      description:
        "Inspect one allowlisted service through a positive projection. Environment values and credentials are never returned.",
      inputSchema: TargetInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ project, service }) =>
      invoke(() => operator.inspectService(project, service)),
  );

  server.registerTool(
    "easypanel_check_service_health",
    {
      description:
        "Return a strict readiness projection for one allowlisted service without probing arbitrary URLs or exposing configuration.",
      inputSchema: TargetInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ project, service }) =>
      invoke(() => operator.checkServiceHealth(project, service)),
  );

  server.registerTool(
    "easypanel_plan_service",
    {
      description:
        "Create a target-bound desired-state plan. Secret environment values must be supplied by secret reference. Planning never authorizes apply.",
      inputSchema: ServiceSpecInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async (spec) =>
      invoke(() => operator.planService(ServiceSpecSchema.parse(spec))),
  );

  server.registerTool(
    "easypanel_apply_service",
    {
      description:
        "Apply exactly one stored service plan by hash after current policy, external approval, TTL, and precondition checks.",
      inputSchema: ApplyServiceInputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ planHash }) =>
      invoke(() => operator.applyPlan(planHash, { requireServiceSpec: true })),
  );

  server.registerTool(
    "easypanel_change_service_state",
    {
      description:
        "Two-phase typed start, stop, or restart for an app. Stop is critical and requires both external approval and independent confirmation artifacts.",
      inputSchema: PlannedLifecycleInputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ project, service, operation, planHash }) => {
      const action = `${operation}_service` as
        | "start_service"
        | "stop_service"
        | "restart_service";
      return invoke(() =>
        planHash === undefined
          ? operator.planOperation(operation, project, service)
          : operator.applyPlan(planHash, { project, service, action }),
      );
    },
  );

  server.registerTool(
    "easypanel_deploy_service",
    {
      description:
        "Two-phase app deployment. Omit planHash to plan; provide that planHash with the same project and service to apply it after external approval.",
      inputSchema: PlannedOperationToolInputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ project, service, planHash }) =>
      invoke(() =>
        planHash === undefined
          ? operator.planOperation("deploy", project, service)
          : operator.applyPlan(planHash, {
              project,
              service,
              action: "deploy_service",
            }),
      ),
  );

  server.registerTool(
    "easypanel_list_deployments",
    {
      description:
        "List bounded, sanitized deployment summaries for one allowlisted service.",
      inputSchema: TargetInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ project, service }) =>
      invoke(() => operator.listDeployments(project, service)),
  );

  server.registerTool(
    "easypanel_get_deployment_status",
    {
      description:
        "Return a sanitized deployment summary only when its opaque id belongs to the requested allowlisted project and service.",
      inputSchema: DeploymentStatusInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ id, project, service }) =>
      invoke(async () => {
        const deployment = await operator.getDeploymentStatus(id, project, service);
        if (
          deployment !== null &&
          (deployment.project !== project || deployment.service !== service)
        ) {
          throw codedError("ACTION_DENIED");
        }
        return deployment;
      }),
  );

  server.registerTool(
    "easypanel_get_sanitized_logs",
    {
      description:
        "Return the fixed policy notice that deployment-log content is disabled in this release; no upstream log is fetched.",
      inputSchema: SanitizedLogsInputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ project, service, maxLines }) =>
      invoke(() => operator.getSanitizedLogs(project, service, maxLines)),
  );

  server.registerTool(
    "easypanel_rotate_deploy_webhook",
    {
      description:
        "Two-phase critical deploy-webhook rotation. Omit planHash to plan; provide that planHash with the same target to apply after external approval.",
      inputSchema: PlannedOperationToolInputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ project, service, planHash }) =>
      invoke(() =>
        planHash === undefined
          ? operator.planOperation("rotate_deploy_webhook", project, service)
          : operator.applyPlan(planHash, {
              project,
              service,
              action: "rotate_deploy_webhook",
            }),
      ),
  );

  server.registerTool(
    "easypanel_destroy_service",
    {
      description:
        "Two-phase critical service destruction. Omit planHash to plan; provide that planHash with the same target to apply after external approval.",
      inputSchema: PlannedOperationToolInputSchema,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ project, service, planHash }) =>
      invoke(() =>
        planHash === undefined
          ? operator.planDestroy(project, service)
          : operator.applyPlan(planHash, {
              project,
              service,
              action: "destroy_service",
            }),
      ),
  );

  // SDK 1.29 serializes its own Zod validation messages into tool results. Some
  // Zod issues include the rejected value, which is incompatible with the
  // no-credential transcript invariant. Keep the high-level registrations for
  // their strict published JSON Schemas, but replace only the call dispatcher
  // with fail-closed validation that returns a fixed code.
  const safelyInvoke = async <Schema extends z.ZodTypeAny>(
    schema: Schema,
    raw: unknown,
    operation: (input: z.output<Schema>) => Promise<unknown>,
  ): Promise<CallToolResult> => {
    if (!isBoundedToolInput(raw)) return errorResult("PLAN_INVALID");
    const parsed = schema.safeParse(raw ?? {});
    if (!parsed.success) return errorResult("PLAN_INVALID");
    return invoke(() => operation(parsed.data));
  };

  server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const raw = request.params.arguments ?? {};
    switch (request.params.name) {
      case "easypanel_capabilities":
        return safelyInvoke(EmptyInputSchema, raw, () => operator.capabilities());
      case "easypanel_list_projects":
        return safelyInvoke(EmptyInputSchema, raw, () => operator.listProjects());
      case "easypanel_list_services":
        return safelyInvoke(ProjectInputSchema, raw, ({ project }) =>
          operator.listServices(project),
        );
      case "easypanel_inspect_service":
        return safelyInvoke(TargetInputSchema, raw, ({ project, service }) =>
          operator.inspectService(project, service),
        );
      case "easypanel_check_service_health":
        return safelyInvoke(TargetInputSchema, raw, ({ project, service }) =>
          operator.checkServiceHealth(project, service),
        );
      case "easypanel_plan_service":
        return safelyInvoke(ServiceSpecInputSchema, raw, (spec) =>
          operator.planService(ServiceSpecSchema.parse(spec)),
        );
      case "easypanel_apply_service":
        return safelyInvoke(ApplyServiceInputSchema, raw, ({ planHash }) =>
          operator.applyPlan(planHash, { requireServiceSpec: true }),
        );
      case "easypanel_change_service_state":
        return safelyInvoke(
          PlannedLifecycleInputSchema,
          raw,
          ({ project, service, operation, planHash }) =>
            planHash === undefined
              ? operator.planOperation(operation, project, service)
              : operator.applyPlan(planHash, {
                  project,
                  service,
                  action: lifecycleAction(operation),
                }),
        );
      case "easypanel_deploy_service":
        return safelyInvoke(
          PlannedOperationToolInputSchema,
          raw,
          ({ project, service, planHash }) =>
            planHash === undefined
              ? operator.planOperation("deploy", project, service)
              : operator.applyPlan(planHash, { project, service, action: "deploy_service" }),
        );
      case "easypanel_list_deployments":
        return safelyInvoke(TargetInputSchema, raw, ({ project, service }) =>
          operator.listDeployments(project, service),
        );
      case "easypanel_get_deployment_status":
        return safelyInvoke(
          DeploymentStatusInputSchema,
          raw,
          ({ id, project, service }) => operator.getDeploymentStatus(id, project, service),
        );
      case "easypanel_get_sanitized_logs":
        return safelyInvoke(
          SanitizedLogsInputSchema,
          raw,
          ({ project, service, maxLines }) =>
            operator.getSanitizedLogs(project, service, maxLines),
        );
      case "easypanel_rotate_deploy_webhook":
        return safelyInvoke(
          PlannedOperationToolInputSchema,
          raw,
          ({ project, service, planHash }) =>
            planHash === undefined
              ? operator.planOperation("rotate_deploy_webhook", project, service)
              : operator.applyPlan(planHash, {
                  project,
                  service,
                  action: "rotate_deploy_webhook",
                }),
        );
      case "easypanel_destroy_service":
        return safelyInvoke(
          PlannedOperationToolInputSchema,
          raw,
          ({ project, service, planHash }) =>
            planHash === undefined
              ? operator.planDestroy(project, service)
              : operator.applyPlan(planHash, { project, service, action: "destroy_service" }),
        );
      default:
        return errorResult("ACTION_DENIED");
    }
  });

  return server;
}

function isBoundedToolInput(value: unknown): boolean {
  try {
    const serialized = JSON.stringify(value);
    return (
      serialized !== undefined &&
      Buffer.byteLength(serialized, "utf8") <= 65_536
    );
  } catch {
    return false;
  }
}

function errorResult(code: string): CallToolResult {
  return {
    content: [{ type: "text", text: code }],
    isError: true,
  };
}

function publicErrorCode(error: unknown): string {
  if (error instanceof z.ZodError) return "PLAN_INVALID";
  const internal = safeErrorCode(error);
  if (internal.startsWith("UPSTREAM_HTTP_")) return "UPSTREAM_ERROR";
  const alias = ERROR_CODE_ALIASES[internal];
  if (alias !== undefined) return alias;
  return PUBLIC_ERROR_CODES.has(internal) ? internal : "INTERNAL_ERROR";
}

function codedError(code: string): Error {
  const error = new Error(code);
  Object.defineProperty(error, "code", { value: code });
  return error;
}

function lifecycleAction(
  operation: "start" | "stop" | "restart",
): "start_service" | "stop_service" | "restart_service" {
  switch (operation) {
    case "start":
      return "start_service";
    case "stop":
      return "stop_service";
    case "restart":
      return "restart_service";
  }
}
