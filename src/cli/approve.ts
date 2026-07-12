#!/usr/bin/env node

import {
  type ApprovalAction,
  type ApprovalPurpose,
  ExternalApprovalStore,
} from "../core/external-approval.js";

const ALLOWED_ACTIONS: readonly ApprovalAction[] = [
  "apply_service",
  "deploy_service",
  "start_service",
  "stop_service",
  "restart_service",
  "destroy_service",
  "rotate_deploy_webhook",
];

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const key = process.env.EASYPANEL_APPROVAL_KEY;
  if (!key || Buffer.byteLength(key, "utf8") < 32) {
    fail("EASYPANEL_APPROVAL_KEY must come from the operator's secret store");
  }
  const action = args.get("action");
  if (!action || !ALLOWED_ACTIONS.includes(action as ApprovalAction)) {
    fail("--action must name an allowed operation");
  }
  const purpose = args.get("purpose");
  if (purpose !== "approval" && purpose !== "confirmation") {
    fail("--purpose must be approval or confirmation");
  }
  const directory = process.env.EASYPANEL_APPROVAL_DIR || ".state/approvals";
  const ttlSeconds = parseTtl(process.env.EASYPANEL_APPROVAL_TTL_SECONDS);
  const store = new ExternalApprovalStore({
    directory,
    key,
    ttlMs: ttlSeconds * 1000,
  });
  await store.create({
    planHash: requiredArg(args, "plan"),
    purpose: purpose as ApprovalPurpose,
    action: action as ApprovalAction,
    project: requiredArg(args, "project"),
    service: requiredArg(args, "service"),
    approver: requiredArg(args, "approver"),
  });
  process.stdout.write("Short-lived Easypanel plan approval created.\n");
}

function parseArgs(values: string[]): Map<string, string> {
  const output = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!flag?.startsWith("--") || !value || value.startsWith("--")) {
      fail("Expected --plan/--action/--purpose/--project/--service/--approver pairs");
    }
    const key = flag.slice(2);
    if (
      !new Set(["plan", "action", "purpose", "project", "service", "approver"]).has(key) ||
      output.has(key)
    ) {
      fail("Unknown or repeated argument");
    }
    output.set(key, value);
  }
  return output;
}

function requiredArg(args: Map<string, string>, name: string): string {
  const value = args.get(name);
  if (!value) fail(`--${name} is required`);
  return value;
}

function parseTtl(value: string | undefined): number {
  if (value === undefined || value === "") return 300;
  if (!/^\d+$/.test(value)) fail("EASYPANEL_APPROVAL_TTL_SECONDS is invalid");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 30 || parsed > 900) {
    fail("EASYPANEL_APPROVAL_TTL_SECONDS must be between 30 and 900");
  }
  return parsed;
}

function fail(message: string): never {
  process.stderr.write(`Approval not created: ${message}\n`);
  process.exit(1);
}

main().catch((error: unknown) => {
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : "FAILED";
  fail(code);
});
