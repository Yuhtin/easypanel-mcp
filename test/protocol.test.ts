import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  BoundedStdioServerTransport,
  BoundedStdioTransportError,
} from "../src/core/bounded-stdio-transport.js";
import { AdmissionGate, AdmissionGateError } from "../src/core/admission-gate.js";
import { disabledJsonSchemaValidator } from "../src/core/disabled-json-schema-validator.js";
import { SecretRegistry } from "../src/core/redaction.js";
import type { EasypanelOperator } from "../src/domain/operator.js";
import { createEasypanelMcpServer } from "../src/server.js";

function requestFrameWithBytes(bytes: number): string {
  const empty = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "ping",
    params: { padding: "" },
  });
  const padding = bytes - Buffer.byteLength(empty, "utf8");
  assert.ok(padding >= 0);
  const frame = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "ping",
    params: { padding: "x".repeat(padding) },
  });
  assert.equal(Buffer.byteLength(frame, "utf8"), bytes);
  return frame;
}

function responseWithBytes(bytes: number, id = 1) {
  const empty = JSON.stringify({ jsonrpc: "2.0", id, result: { padding: "" } });
  const padding = bytes - Buffer.byteLength(empty, "utf8");
  assert.ok(padding >= 0);
  const message = {
    jsonrpc: "2.0" as const,
    id,
    result: { padding: "x".repeat(padding) },
  };
  assert.equal(Buffer.byteLength(JSON.stringify(message), "utf8"), bytes);
  return message;
}

class BlockedWritable extends Writable {
  #pending?: (error?: Error | null) => void;
  readonly chunks: Buffer[] = [];

  constructor() {
    super({ highWaterMark: 1 });
  }

  override _write(
    _chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(Buffer.from(_chunk));
    this.#pending = callback;
  }

  release(): void {
    const callback = this.#pending;
    this.#pending = undefined;
    callback?.();
  }
}

test("disabled JSON-schema validation always fails closed", () => {
  const validate = disabledJsonSchemaValidator.getValidator<unknown>({});
  assert.deepEqual(validate({ accepted: "must never happen" }), {
    valid: false,
    data: undefined,
    errorMessage: "VALIDATION_DISABLED",
  });
});

test("tool admission is fail-fast, bounded, and never queues inputs", () => {
  const gate = new AdmissionGate(2);
  const releaseFirst = gate.enter();
  const releaseSecond = gate.enter();
  assert.throws(
    () => gate.enter(),
    (error: unknown) =>
      error instanceof AdmissionGateError && error.code === "SERVER_BUSY",
  );
  releaseFirst();
  releaseFirst();
  const releaseThird = gate.enter();
  releaseSecond();
  releaseThird();
});

test("MCP initialize/list/call exposes only the fixed tool registry and masks rejected input", async (t) => {
  // These calls are intentionally rejected before an operator method can run.
  const server = createEasypanelMcpServer(
    {} as unknown as EasypanelOperator,
    new SecretRegistry(),
  );
  const client = new Client(
    { name: "offline-protocol-test", version: "1.0.0" },
    { jsonSchemaValidator: disabledJsonSchemaValidator },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => {
    await client.close();
    await server.close();
  });

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const listed = await client.listTools();
  assert.equal(listed.tools.length, 14);
  assert.deepEqual(
    listed.tools.map((tool) => tool.name).sort(),
    [
      "easypanel_apply_service",
      "easypanel_capabilities",
      "easypanel_change_service_state",
      "easypanel_check_service_health",
      "easypanel_deploy_service",
      "easypanel_destroy_service",
      "easypanel_get_deployment_status",
      "easypanel_get_sanitized_logs",
      "easypanel_inspect_service",
      "easypanel_list_deployments",
      "easypanel_list_projects",
      "easypanel_list_services",
      "easypanel_plan_service",
      "easypanel_rotate_deploy_webhook",
    ],
  );
  assert.match(
    listed.tools.find((tool) => tool.name === "easypanel_get_sanitized_logs")?.description ?? "",
    /disabled|desativado/i,
  );

  const canary = "literal-secret-that-must-not-be-echoed";
  const rejected = await client.callTool({
    name: "easypanel_plan_service",
    arguments: {
      project: "sandbox",
      service: "api",
      kind: "app",
      environment: {
        merge: { DATABASE_URL: { from: "literal", value: canary } },
        remove: [],
      },
    },
  });
  const renderedRejected = JSON.stringify(rejected);
  assert.equal(rejected.isError, true);
  assert.equal(renderedRejected.includes("PLAN_INVALID"), true);
  assert.equal(renderedRejected.includes(canary), false);

  const unknown = await client.callTool({
    name: "easypanel_raw_rpc",
    arguments: {},
  });
  const renderedUnknown = JSON.stringify(unknown);
  assert.equal(unknown.isError, true);
  assert.equal(renderedUnknown.includes("ACTION_DENIED"), true);
});

test("MCP tool calls share the bootstrap registry but isolate runtime secrets per invocation", async (t) => {
  const registry = new SecretRegistry();
  const permanent = "permanent-protocol-secret";
  const dynamic: string[] = [];
  registry.add(permanent);
  const operator = {
    async capabilities() {
      const value = `dynamic-protocol-secret-${dynamic.length}`;
      dynamic.push(value);
      registry.add(value);
      await Promise.resolve();
      return { permanent, value };
    },
  } as unknown as EasypanelOperator;
  const server = createEasypanelMcpServer(operator, registry);
  const client = new Client(
    { name: "offline-scope-test", version: "1.0.0" },
    { jsonSchemaValidator: disabledJsonSchemaValidator },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => {
    await client.close();
    await server.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const first = JSON.stringify(await client.callTool({
    name: "easypanel_capabilities",
    arguments: {},
  }));
  const second = JSON.stringify(await client.callTool({
    name: "easypanel_capabilities",
    arguments: {},
  }));
  assert.equal(first.includes(permanent), false);
  assert.equal(second.includes(permanent), false);
  assert.equal(first.includes(dynamic[0] as string), false);
  assert.equal(second.includes(dynamic[1] as string), false);
  assert.equal(registry.redactText(dynamic[0] as string), dynamic[0]);
  assert.throws(() => registry.add("unscoped-protocol-secret"));
});

test("bounded stdio frames one JSON-RPC object per newline on injected streams", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });

  const received = new Promise<unknown>((resolve, reject) => {
    transport.onmessage = resolve;
    transport.onerror = reject;
  });
  await transport.start();
  input.write('{"jsonrpc":"2.0","id":7,"method":"ping"}\n');
  assert.deepEqual(await received, { jsonrpc: "2.0", id: 7, method: "ping" });

  const framed: string[] = [];
  output.on("data", (chunk: Buffer) => {
    framed.push(chunk.toString("utf8"));
  });
  await Promise.all([
    transport.send({ jsonrpc: "2.0", id: 7, result: {} }),
    transport.send({ jsonrpc: "2.0", id: 8, result: {} }),
  ]);
  assert.equal(
    framed.join(""),
    '{"jsonrpc":"2.0","id":7,"result":{}}\n' +
      '{"jsonrpc":"2.0","id":8,"result":{}}\n',
  );
});

test("bounded stdio accepts exact frame limits and rejects one byte above", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output, 96, 96, 194);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });
  const received = new Promise<unknown>((resolve, reject) => {
    transport.onmessage = resolve;
    transport.onerror = reject;
  });
  const outputChunks: Buffer[] = [];
  output.on("data", (chunk: Buffer) => outputChunks.push(chunk));
  await transport.start();
  const exactRequest = requestFrameWithBytes(96);
  input.write(`${exactRequest}\n`);
  assert.deepEqual(await received, JSON.parse(exactRequest));
  await transport.send(responseWithBytes(96));
  assert.equal(Buffer.concat(outputChunks).byteLength, 97);

  const tooLargeInput = new PassThrough();
  const tooLargeOutput = new PassThrough();
  const tooLarge = new BoundedStdioServerTransport(
    tooLargeInput,
    tooLargeOutput,
    96,
    96,
    194,
  );
  t.after(async () => {
    await tooLarge.close();
    tooLargeInput.destroy();
    tooLargeOutput.destroy();
  });
  const failed = new Promise<Error>((resolve) => {
    tooLarge.onerror = resolve;
  });
  await tooLarge.start();
  tooLargeInput.write(`${requestFrameWithBytes(97)}\n`);
  const error = await failed;
  assert.equal(
    error instanceof BoundedStdioTransportError &&
      error.code === "STDIO_FRAME_TOO_LARGE",
    true,
  );

  const outputInput = new PassThrough();
  const outputSink = new PassThrough();
  const outputTooLarge = new BoundedStdioServerTransport(
    outputInput,
    outputSink,
    64,
    96,
    194,
  );
  t.after(async () => {
    await outputTooLarge.close();
    outputInput.destroy();
    outputSink.destroy();
  });
  await outputTooLarge.start();
  await assert.rejects(
    outputTooLarge.send(responseWithBytes(97)),
    (candidate: unknown) =>
      candidate instanceof BoundedStdioTransportError &&
      candidate.code === "STDIO_FRAME_TOO_LARGE",
  );
});

test("bounded stdio rejects a fragmented frame before unbounded accumulation", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output, 64);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });

  const failed = new Promise<Error>((resolve) => {
    transport.onerror = resolve;
  });
  let closed = 0;
  transport.onclose = () => {
    closed += 1;
  };
  await transport.start();
  await assert.rejects(
    transport.start(),
    (error: unknown) =>
      error instanceof BoundedStdioTransportError &&
      error.code === "STDIO_ALREADY_STARTED",
  );
  input.write("x".repeat(40));
  input.write("y".repeat(25));
  const error = await failed;
  assert.equal(
    error instanceof BoundedStdioTransportError &&
      error.code === "STDIO_FRAME_TOO_LARGE",
    true,
  );
  assert.equal(closed, 1);
  assert.equal(input.listenerCount("data"), 0);
  await transport.close();
  assert.equal(closed, 1);
});

test("bounded stdio accepts multiple CRLF/LF frames without mixing them", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });
  const messages: unknown[] = [];
  transport.onmessage = (message) => {
    messages.push(message);
  };
  await transport.start();
  input.write(
    '{"jsonrpc":"2.0","id":1,"method":"ping"}\r\n' +
      '{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
  );
  assert.deepEqual(messages, [
    { jsonrpc: "2.0", id: 1, method: "ping" },
    { jsonrpc: "2.0", id: 2, method: "ping" },
  ]);
});

test("bounded stdio rejects invalid UTF-8 with a fixed code and no echo", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });
  const failed = new Promise<Error>((resolve) => {
    transport.onerror = resolve;
  });
  await transport.start();
  input.write(Buffer.from([0xff, 0x0a]));
  const error = await failed;
  assert.equal(
    error instanceof BoundedStdioTransportError &&
      error.code === "STDIO_FRAME_INVALID",
    true,
  );
  assert.equal(output.readableLength, 0);
});

test("bounded stdio rejects blank frames instead of discarding following input", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output);
  t.after(async () => {
    await transport.close();
    input.destroy();
    output.destroy();
  });
  const messages: unknown[] = [];
  const failed = new Promise<Error>((resolve) => {
    transport.onerror = resolve;
  });
  transport.onmessage = (message) => messages.push(message);
  await transport.start();
  input.write('\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n');
  const error = await failed;
  assert.equal(
    error instanceof BoundedStdioTransportError &&
      error.code === "STDIO_FRAME_INVALID",
    true,
  );
  assert.deepEqual(messages, []);
});

test("bounded stdio closes when aggregate backpressured output exceeds its queue cap", async (t) => {
  const input = new PassThrough();
  const output = new BlockedWritable();
  const transport = new BoundedStdioServerTransport(input, output, 64, 128, 256);
  t.after(async () => {
    output.release();
    await transport.close();
    input.destroy();
    output.destroy();
  });
  const errors: BoundedStdioTransportError[] = [];
  let closes = 0;
  transport.onerror = (error) => {
    if (error instanceof BoundedStdioTransportError) errors.push(error);
  };
  transport.onclose = () => {
    closes += 1;
  };
  await transport.start();
  const first = transport.send(responseWithBytes(120, 1));
  await Promise.resolve();
  const second = transport.send(responseWithBytes(120, 2));
  const overflow = transport.send(responseWithBytes(120, 3));
  const outcomes = await Promise.allSettled([first, second, overflow]);
  const overflowOutcome = outcomes[2];
  assert.equal(
    overflowOutcome?.status === "rejected" &&
      overflowOutcome.reason instanceof BoundedStdioTransportError &&
      overflowOutcome.reason.code === "STDIO_QUEUE_OVERFLOW",
    true,
  );
  assert.equal(errors.at(-1)?.code, "STDIO_QUEUE_OVERFLOW");
  assert.equal(closes, 1);
  output.release();
});

test("bounded stdio also caps the number of queued output frames", async (t) => {
  const input = new PassThrough();
  const output = new BlockedWritable();
  const transport = new BoundedStdioServerTransport(input, output, 64, 128, 1_024, 2);
  t.after(async () => {
    output.release();
    await transport.close();
    input.destroy();
    output.destroy();
  });
  await transport.start();
  const first = transport.send(responseWithBytes(64, 1));
  await Promise.resolve();
  const second = transport.send(responseWithBytes(64, 2));
  const overflow = transport.send(responseWithBytes(64, 3));
  const outcomes = await Promise.allSettled([first, second, overflow]);
  const overflowOutcome = outcomes[2];
  assert.equal(
    overflowOutcome?.status === "rejected" &&
      overflowOutcome.reason instanceof BoundedStdioTransportError &&
      overflowOutcome.reason.code === "STDIO_QUEUE_OVERFLOW",
    true,
  );
  output.release();
});

test("bounded stdio resumes after drain and preserves queued response order", async (t) => {
  const input = new PassThrough();
  const output = new BlockedWritable();
  const transport = new BoundedStdioServerTransport(input, output, 64, 128, 1_024, 4);
  t.after(async () => {
    output.release();
    await transport.close();
    input.destroy();
    output.destroy();
  });
  await transport.start();
  const first = transport.send(responseWithBytes(64, 1));
  await Promise.resolve();
  const second = transport.send(responseWithBytes(64, 2));
  assert.equal(output.chunks.length, 1);
  output.release();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(output.chunks.length, 2);
  output.release();
  await Promise.all([first, second]);
  assert.equal(
    Buffer.concat(output.chunks).toString("utf8"),
    `${JSON.stringify(responseWithBytes(64, 1))}\n${JSON.stringify(responseWithBytes(64, 2))}\n`,
  );
});

test("bounded stdio closes and rejects a pending send on abrupt input close", async (t) => {
  const input = new PassThrough();
  const output = new BlockedWritable();
  const transport = new BoundedStdioServerTransport(input, output, 64, 128, 1_024, 4);
  t.after(() => {
    output.release();
    input.destroy();
    output.destroy();
  });
  let closes = 0;
  transport.onclose = () => {
    closes += 1;
  };
  await transport.start();
  const pending = transport.send(responseWithBytes(64));
  await Promise.resolve();
  input.emit("close");
  await assert.rejects(
    pending,
    (error: unknown) =>
      error instanceof BoundedStdioTransportError && error.code === "STDIO_CLOSED",
  );
  assert.equal(closes, 1);
});

test("bounded stdio reports fixed I/O errors after marking itself closed", async (t) => {
  const input = new PassThrough();
  const output = new PassThrough();
  const transport = new BoundedStdioServerTransport(input, output);
  t.after(() => {
    input.destroy();
    output.destroy();
  });
  const observed: string[] = [];
  let closes = 0;
  transport.onerror = (error) => {
    observed.push(error instanceof BoundedStdioTransportError ? error.code : "unexpected");
    void transport.send({ jsonrpc: "2.0", id: 1, result: {} }).catch((sendError: unknown) => {
      observed.push(
        sendError instanceof BoundedStdioTransportError ? sendError.code : "unexpected",
      );
    });
  };
  transport.onclose = () => {
    closes += 1;
  };
  await transport.start();
  input.emit("error", new Error("untrusted-secret-bearing-error"));
  await Promise.resolve();
  assert.deepEqual(observed, ["STDIO_IO_ERROR", "STDIO_CLOSED"]);
  assert.equal(closes, 1);
});

test("bounded stdio rejects partial EOF and oversized frame batches", async (t) => {
  const partialInput = new PassThrough();
  const partialOutput = new PassThrough();
  const partial = new BoundedStdioServerTransport(partialInput, partialOutput);
  const partialFailure = new Promise<Error>((resolve) => {
    partial.onerror = resolve;
  });
  await partial.start();
  partialInput.end('{"jsonrpc":"2.0"');
  const partialError = await partialFailure;
  assert.equal(
    partialError instanceof BoundedStdioTransportError &&
      partialError.code === "STDIO_FRAME_INVALID",
    true,
  );

  const batchInput = new PassThrough();
  const batchOutput = new PassThrough();
  const batch = new BoundedStdioServerTransport(batchInput, batchOutput);
  const batchFailure = new Promise<Error>((resolve) => {
    batch.onerror = resolve;
  });
  await batch.start();
  batchInput.write(
    Array.from(
      { length: 257 },
      (_, id) => JSON.stringify({ jsonrpc: "2.0", id, method: "ping" }),
    ).join("\n") + "\n",
  );
  const batchError = await batchFailure;
  assert.equal(
    batchError instanceof BoundedStdioTransportError &&
      batchError.code === "STDIO_BATCH_OVERFLOW",
    true,
  );

  t.after(async () => {
    await partial.close();
    await batch.close();
    partialInput.destroy();
    partialOutput.destroy();
    batchInput.destroy();
    batchOutput.destroy();
  });
});
