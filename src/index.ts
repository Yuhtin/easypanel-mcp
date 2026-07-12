#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { BoundedStdioServerTransport } from "./core/bounded-stdio-transport.js";
import { RemoteMcpHttpServer } from "./remote/streamable-http-server.js";
import { createConfiguredRuntime } from "./runtime.js";

/** Backwards-compatible helper for local stdio integrations and tests. */
export async function createConfiguredServer(
  env: NodeJS.ProcessEnv = process.env,
): Promise<McpServer> {
  const runtime = await createConfiguredRuntime(env);
  if (runtime.config.transport !== "stdio") throw codedBootFailure();
  return runtime.createMcpServer();
}

export async function main(): Promise<void> {
  const runtime = await createConfiguredRuntime(process.env);
  if (runtime.config.transport === "http") {
    const remote = await RemoteMcpHttpServer.start({ runtime });
    installRemoteShutdown(remote, runtime);
    return;
  }

  const server = runtime.createMcpServer();
  await server.connect(new BoundedStdioServerTransport());
}

function installRemoteShutdown(
  remote: RemoteMcpHttpServer,
  runtime: Awaited<ReturnType<typeof createConfiguredRuntime>>,
): void {
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    void Promise.allSettled([remote.close(), runtime.close()]).finally(() => {
      process.exitCode = 0;
    });
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

function codedBootFailure(): Error {
  const error = new Error("BOOT_FAILED");
  Object.defineProperty(error, "code", { value: "INCOMPATIBLE_CAPABILITIES" });
  return error;
}

function isDirectExecution(): boolean {
  const entrypoint = process.argv[1];
  return entrypoint !== undefined && import.meta.url === pathToFileURL(entrypoint).href;
}

if (isDirectExecution()) {
  void main().catch(() => {
    process.exitCode = 1;
    try {
      process.stderr.write("EASYPANEL_MCP_BOOT_FAILED\n");
    } catch {
      // There is no safe diagnostic fallback when stderr itself is unavailable.
    }
  });
}
