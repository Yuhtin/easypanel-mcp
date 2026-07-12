import { AsyncLocalStorage } from "node:async_hooks";

// The MCP SDK exposes a cancellation signal only for a client-supplied
// notifications/cancelled message. The HTTP edge also owns a wall-clock
// deadline, so carry that signal through the asynchronous tool call without
// turning it into a forged client notification. Gateways can then abort their
// own fetches and settle the real MCP request normally.
const invocationAbort = new AsyncLocalStorage<AbortSignal>();

export function runWithInvocationAbort<T>(
  signal: AbortSignal | undefined,
  operation: () => T,
): T {
  if (signal === undefined) return operation();
  return invocationAbort.run(signal, operation);
}

export function currentInvocationAbort(): AbortSignal | undefined {
  return invocationAbort.getStore();
}
