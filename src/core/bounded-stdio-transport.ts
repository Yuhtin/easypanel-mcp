import type { Readable, Writable } from "node:stream";

import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  JSONRPCMessageSchema,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";

export const MAX_STDIO_FRAME_BYTES = 131_072;
export const MAX_STDIO_OUTPUT_FRAME_BYTES = 4_325_376;
export const MAX_STDIO_QUEUED_BYTES = 8_650_754;
export const MAX_STDIO_QUEUED_FRAMES = 256;
export const MAX_STDIO_CHUNK_BYTES = 1_048_576;
export const MAX_STDIO_FRAMES_PER_CHUNK = 256;

export class BoundedStdioTransportError extends Error {
  readonly code:
    | "STDIO_ALREADY_STARTED"
    | "STDIO_CLOSED"
    | "STDIO_FRAME_INVALID"
    | "STDIO_FRAME_TOO_LARGE"
    | "STDIO_BATCH_OVERFLOW"
    | "STDIO_QUEUE_OVERFLOW"
    | "STDIO_IO_ERROR";

  constructor(code: BoundedStdioTransportError["code"]) {
    super(code);
    this.name = "BoundedStdioTransportError";
    this.code = code;
  }
}

/** Newline-delimited MCP stdio with a hard inbound cap before concat/JSON parse. */
export class BoundedStdioServerTransport implements Transport {
  onclose: Transport["onclose"] = undefined;
  onerror: Transport["onerror"] = undefined;
  onmessage: Transport["onmessage"] = undefined;

  readonly #input: Readable;
  readonly #output: Writable;
  readonly #maximumFrameBytes: number;
  readonly #maximumOutputFrameBytes: number;
  readonly #maximumQueuedBytes: number;
  readonly #maximumQueuedFrames: number;
  readonly #pendingDrainRejectors = new Set<(error: Error) => void>();
  readonly #buffer: Buffer;
  #bufferedBytes = 0;
  #queuedBytes = 0;
  #queuedFrames = 0;
  #started = false;
  #closed = false;
  #closeNotified = false;
  #sendTail: Promise<void> = Promise.resolve();

  readonly #onData = (chunk: unknown): void => {
    this.#acceptChunk(chunk);
  };

  readonly #onInputError = (): void => {
    this.#fail("STDIO_IO_ERROR");
  };

  readonly #onOutputError = (): void => {
    this.#fail("STDIO_IO_ERROR");
  };

  readonly #onInputEnd = (): void => {
    if (this.#bufferedBytes > 0) {
      this.#fail("STDIO_FRAME_INVALID");
      return;
    }
    this.#closeNow();
  };

  readonly #onInputClose = (): void => {
    this.#closeNow();
  };

  readonly #onOutputClose = (): void => {
    this.#closeNow();
  };

  constructor(
    input: Readable = process.stdin,
    output: Writable = process.stdout,
    maximumFrameBytes = MAX_STDIO_FRAME_BYTES,
    maximumOutputFrameBytes = MAX_STDIO_OUTPUT_FRAME_BYTES,
    maximumQueuedBytes = MAX_STDIO_QUEUED_BYTES,
    maximumQueuedFrames = MAX_STDIO_QUEUED_FRAMES,
  ) {
    if (
      !Number.isSafeInteger(maximumFrameBytes) ||
      maximumFrameBytes < 64 ||
      maximumFrameBytes > 1_048_576 ||
      !Number.isSafeInteger(maximumOutputFrameBytes) ||
      maximumOutputFrameBytes < maximumFrameBytes ||
      maximumOutputFrameBytes > 4_500_000 ||
      !Number.isSafeInteger(maximumQueuedBytes) ||
      maximumQueuedBytes < maximumOutputFrameBytes + 1 ||
      maximumQueuedBytes > 9_000_000 ||
      !Number.isSafeInteger(maximumQueuedFrames) ||
      maximumQueuedFrames < 1 ||
      maximumQueuedFrames > 1_024
    ) {
      throw new BoundedStdioTransportError("STDIO_FRAME_INVALID");
    }
    this.#input = input;
    this.#output = output;
    this.#maximumFrameBytes = maximumFrameBytes;
    this.#maximumOutputFrameBytes = maximumOutputFrameBytes;
    this.#maximumQueuedBytes = maximumQueuedBytes;
    this.#maximumQueuedFrames = maximumQueuedFrames;
    this.#buffer = Buffer.alloc(maximumFrameBytes);
  }

  async start(): Promise<void> {
    if (this.#started || this.#closed) {
      throw new BoundedStdioTransportError("STDIO_ALREADY_STARTED");
    }
    this.#started = true;
    this.#input.on("data", this.#onData);
    this.#input.on("error", this.#onInputError);
    this.#input.on("end", this.#onInputEnd);
    this.#input.on("close", this.#onInputClose);
    this.#output.on("error", this.#onOutputError);
    this.#output.on("close", this.#onOutputClose);
  }

  send(
    message: JSONRPCMessage,
    _options?: TransportSendOptions,
  ): Promise<void> {
    let frame: Buffer;
    try {
      if (!this.#started || this.#closed) {
        throw new BoundedStdioTransportError("STDIO_CLOSED");
      }
      frame = this.#serialize(message);
      if (
        this.#queuedFrames >= this.#maximumQueuedFrames ||
        this.#queuedBytes > this.#maximumQueuedBytes - frame.byteLength
      ) {
        this.#fail("STDIO_QUEUE_OVERFLOW");
        throw new BoundedStdioTransportError("STDIO_QUEUE_OVERFLOW");
      }
      this.#queuedBytes += frame.byteLength;
      this.#queuedFrames += 1;
    } catch (error) {
      return Promise.reject(error);
    }

    const operation = this.#sendTail
      .then(() => this.#writeFrame(frame))
      .finally(() => {
        this.#queuedBytes -= frame.byteLength;
        this.#queuedFrames -= 1;
      });
    this.#sendTail = operation.catch(() => undefined);
    return operation;
  }

  async close(): Promise<void> {
    this.#closeNow();
  }

  #serialize(message: JSONRPCMessage): Buffer {
    let serialized: string;
    try {
      const candidate = JSON.stringify(message);
      if (candidate === undefined) throw new TypeError("invalid frame");
      serialized = candidate;
    } catch {
      this.#fail("STDIO_FRAME_INVALID");
      throw new BoundedStdioTransportError("STDIO_FRAME_INVALID");
    }
    const frame = Buffer.from(`${serialized}\n`, "utf8");
    if (frame.byteLength - 1 > this.#maximumOutputFrameBytes) {
      this.#fail("STDIO_FRAME_TOO_LARGE");
      throw new BoundedStdioTransportError("STDIO_FRAME_TOO_LARGE");
    }
    return frame;
  }

  async #writeFrame(frame: Buffer): Promise<void> {
    if (!this.#started || this.#closed) {
      throw new BoundedStdioTransportError("STDIO_CLOSED");
    }
    let accepted: boolean;
    try {
      accepted = this.#output.write(frame);
    } catch {
      this.#fail("STDIO_IO_ERROR");
      throw new BoundedStdioTransportError("STDIO_IO_ERROR");
    }
    if (accepted) return;

    await new Promise<void>((resolve, reject) => {
      const rejectPending = (error: Error): void => {
        cleanup();
        reject(error);
      };
      const onDrain = (): void => {
        cleanup();
        resolve();
      };
      const cleanup = (): void => {
        this.#output.off("drain", onDrain);
        this.#pendingDrainRejectors.delete(rejectPending);
      };
      this.#pendingDrainRejectors.add(rejectPending);
      this.#output.once("drain", onDrain);
      if (this.#closed) {
        rejectPending(new BoundedStdioTransportError("STDIO_CLOSED"));
      }
    });
  }

  #acceptChunk(chunk: unknown): void {
    if (this.#closed) return;
    let bytes: Buffer;
    if (Buffer.isBuffer(chunk)) bytes = chunk;
    else if (chunk instanceof Uint8Array) bytes = Buffer.from(chunk);
    else if (typeof chunk === "string") bytes = Buffer.from(chunk, "utf8");
    else {
      this.#fail("STDIO_FRAME_INVALID");
      return;
    }
    if (bytes.byteLength > MAX_STDIO_CHUNK_BYTES) {
      this.#fail("STDIO_BATCH_OVERFLOW");
      return;
    }

    let offset = 0;
    let frames = 0;
    while (offset < bytes.length && !this.#closed) {
      const newline = bytes.indexOf(0x0a, offset);
      if (newline === -1) {
        this.#append(bytes.subarray(offset));
        return;
      }
      if (!this.#append(bytes.subarray(offset, newline))) return;
      frames += 1;
      if (frames > MAX_STDIO_FRAMES_PER_CHUNK) {
        this.#fail("STDIO_BATCH_OVERFLOW");
        return;
      }
      const bufferedBytes = this.#bufferedBytes;
      let frame = this.#buffer.subarray(0, bufferedBytes);
      this.#bufferedBytes = 0;
      if (frame.at(-1) === 0x0d) frame = frame.subarray(0, -1);
      if (frame.length === 0) {
        this.#buffer.fill(0, 0, bufferedBytes);
        this.#fail("STDIO_FRAME_INVALID");
        return;
      }
      const dispatched = this.#dispatchFrame(frame);
      this.#buffer.fill(0, 0, bufferedBytes);
      if (!dispatched) return;
      offset = newline + 1;
    }
  }

  #append(segment: Uint8Array): boolean {
    const total = this.#bufferedBytes + segment.byteLength;
    if (total > this.#maximumFrameBytes) {
      this.#fail("STDIO_FRAME_TOO_LARGE");
      return false;
    }
    if (segment.byteLength > 0) {
      Buffer.from(segment).copy(this.#buffer, this.#bufferedBytes);
      this.#bufferedBytes = total;
    }
    return true;
  }

  #dispatchFrame(frame: Uint8Array): boolean {
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(frame);
      const message = JSONRPCMessageSchema.parse(JSON.parse(text));
      this.onmessage?.(message);
      return true;
    } catch {
      this.#fail("STDIO_FRAME_INVALID");
      return false;
    }
  }

  #fail(code: BoundedStdioTransportError["code"]): void {
    if (this.#closed) return;
    const error = new BoundedStdioTransportError(code);
    // Mark terminal and reject pending output before invoking consumer code, so
    // an onerror callback cannot re-enter #fail recursively.
    this.#closeNow(error, false);
    try {
      this.onerror?.(error);
    } catch {
      // A consumer callback cannot make a malformed frame safe to continue.
    } finally {
      this.#notifyClose();
    }
  }

  #closeNow(
    error = new BoundedStdioTransportError("STDIO_CLOSED"),
    notify = true,
  ): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#input.off("data", this.#onData);
    this.#input.off("error", this.#onInputError);
    this.#input.off("end", this.#onInputEnd);
    this.#input.off("close", this.#onInputClose);
    this.#output.off("error", this.#onOutputError);
    this.#output.off("close", this.#onOutputClose);
    if (this.#input.listenerCount("data") === 0) this.#input.pause();
    this.#buffer.fill(0);
    this.#bufferedBytes = 0;
    for (const reject of [...this.#pendingDrainRejectors]) reject(error);
    this.#pendingDrainRejectors.clear();
    if (notify) this.#notifyClose();
  }

  #notifyClose(): void {
    if (this.#closeNotified) return;
    this.#closeNotified = true;
    try {
      this.onclose?.();
    } catch {
      // Close is terminal and must stay idempotent even if a callback throws.
    }
  }
}
