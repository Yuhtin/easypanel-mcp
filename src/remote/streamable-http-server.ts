import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import {
  CallToolRequestSchema,
  InitializeRequestSchema,
  InitializedNotificationSchema,
  JSONRPCMessageSchema,
  JSONRPCResultResponseSchema,
  ListToolsRequestSchema,
  PingRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import type { RemoteHttpConfig } from "../config.js";
import { AdmissionGate } from "../core/admission-gate.js";
import { runWithInvocationAbort } from "../core/invocation-abort.js";
import type { ConfiguredRuntime } from "../runtime.js";

const MAX_RESPONSE_BYTES = 2_200_000;
const MAX_RESPONSE_CHUNKS = 256;
const MAX_REQUEST_CHUNKS = 256;
const MAX_URL_BYTES = 1_024;
const MAX_HEADER_VALUE_BYTES = 512;
const DEFAULT_ABORT_SETTLEMENT_GRACE_MS = 5_000;
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ALLOWED_SESSION_METHODS = new Set([
  "notifications/initialized",
  "tools/list",
  "tools/call",
  "ping",
]);
// Remote HTTP is deliberately a small observation surface. It excludes
// capability refresh and planning: bootstrap warms discovery once, and all
// remaining tools have a verified upper bound of six retryable upstream calls.
// Planning and mutations stay on local stdio until an external asymmetric
// approval design is available.
const REMOTE_READONLY_TOOLS = new Set([
  "easypanel_list_projects",
  "easypanel_list_services",
  "easypanel_inspect_service",
  "easypanel_check_service_health",
  "easypanel_list_deployments",
  "easypanel_get_deployment_status",
  "easypanel_get_sanitized_logs",
]);
type SessionMethod =
  | "initialize"
  | "notifications/initialized"
  | "tools/list"
  | "tools/call"
  | "ping";
type RpcRequestId = string | number;

interface MaterializedTransportResponse {
  readonly status: number;
  readonly body: string;
  readonly sessionId?: string;
  protocolVersion?: string;
}

interface TransportResponseExpectation {
  expectedRequestId?: RpcRequestId;
  expectedSessionId?: string;
  requireSessionId?: boolean;
  requireProtocolVersion?: boolean;
  method?: SessionMethod;
}

interface RemoteSession {
  readonly id: string;
  readonly server: McpServer;
  readonly transport: WebStandardStreamableHTTPServerTransport;
  readonly createdAt: number;
  lastSeenAt: number;
  busy: boolean;
  initialized: boolean;
  clientReady: boolean;
  protocolVersion?: string;
  activeRequest?: {
    readonly transportWork: Promise<Response>;
    readonly abort: () => void;
  };
}

export interface RemoteMcpHttpServerOptions {
  runtime: ConfiguredRuntime;
  /** Test-only listener override. Production always uses validated config. */
  port?: number;
  /** Test-only deadline override; accepted only for the bundled fake fixture. */
  requestDeadlineMs?: number;
  /** Test-only abort-settlement grace override; accepted only for the fake fixture. */
  abortSettlementGraceMs?: number;
  /** Test-only fatal hook; production exits non-zero after failed recovery. */
  onFatal?: (error: Error) => void;
}

/**
 * Minimal Streamable HTTP edge for a single trusted operator.
 *
 * It intentionally supports only authenticated, stateful POST/DELETE MCP
 * traffic with JSON responses. There is no SSE, CORS, replay, browser auth,
 * token in URL, or remotely mutable policy. The runtime config rejects every
 * access mode other than readonly for this transport.
 */
export class RemoteMcpHttpServer {
  readonly #runtime: ConfiguredRuntime;
  readonly #config: RemoteHttpConfig;
  readonly #requestAdmission: AdmissionGate;
  readonly #sessions = new Map<string, RemoteSession>();
  readonly #server: Server;
  readonly #port: number;
  readonly #requestDeadlineMs: number;
  readonly #abortSettlementGraceMs: number;
  readonly #cleanupTimer: NodeJS.Timeout;
  readonly #pendingSessionIds = new Set<string>();
  readonly #fatalHandler: (error: Error) => void;
  #listenerClose?: Promise<void>;
  #pendingInitializations = 0;
  #closed = false;

  private constructor(options: RemoteMcpHttpServerOptions, config: RemoteHttpConfig) {
    this.#runtime = options.runtime;
    this.#config = config;
    this.#requestAdmission = new AdmissionGate(config.maxConcurrentRequests);
    this.#port = options.port ?? config.port;
    if (
      (options.requestDeadlineMs !== undefined || options.abortSettlementGraceMs !== undefined) &&
      (options.runtime.config.fakeFixture === undefined ||
        (options.requestDeadlineMs !== undefined &&
          (!Number.isSafeInteger(options.requestDeadlineMs) ||
            options.requestDeadlineMs < 10 ||
            options.requestDeadlineMs > config.requestDeadlineMs)) ||
        (options.abortSettlementGraceMs !== undefined &&
          (!Number.isSafeInteger(options.abortSettlementGraceMs) ||
            options.abortSettlementGraceMs < 10 ||
            options.abortSettlementGraceMs > DEFAULT_ABORT_SETTLEMENT_GRACE_MS)))
    ) {
      throw new RemoteHttpServerError("CONFIG_INVALID");
    }
    if (
      options.onFatal !== undefined &&
      (options.runtime.config.fakeFixture === undefined || typeof options.onFatal !== "function")
    ) {
      throw new RemoteHttpServerError("CONFIG_INVALID");
    }
    this.#requestDeadlineMs = options.requestDeadlineMs ?? config.requestDeadlineMs;
    this.#abortSettlementGraceMs =
      options.abortSettlementGraceMs ?? DEFAULT_ABORT_SETTLEMENT_GRACE_MS;
    this.#fatalHandler = options.onFatal ?? (() => process.exit(1));
    this.#server = createServer(
      { maxHeaderSize: 8_192 },
      (request, response) => {
        void this.#handle(request, response);
      },
    );
    this.#server.headersTimeout = 10_000;
    this.#server.requestTimeout = 30_000;
    this.#server.keepAliveTimeout = 5_000;
    this.#server.timeout = this.#requestDeadlineMs + 5_000;
    this.#server.maxRequestsPerSocket = 100;
    this.#server.maxConnections = Math.max(
      config.maxSessions + 2,
      config.maxConcurrentRequests * 2,
    );
    this.#server.on("timeout", (socket) => socket.destroy());
    this.#server.on("checkContinue", (_request, response) => {
      applySecurityHeaders(response);
      writeError(response, 417, "EXPECTATION_REJECTED");
    });
    this.#server.on("clientError", (_error, socket) => {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    });
    this.#cleanupTimer = setInterval(() => {
      void this.#expireIdleSessions();
    }, Math.min(config.sessionIdleMs, 60_000));
    this.#cleanupTimer.unref();
  }

  static async start(options: RemoteMcpHttpServerOptions): Promise<RemoteMcpHttpServer> {
    const config = options.runtime.config.remoteHttp;
    if (config === undefined || options.runtime.config.transport !== "http") {
      throw new RemoteHttpServerError("CONFIG_INVALID");
    }
    const service = new RemoteMcpHttpServer(options, config);
    try {
      await service.#listen();
      return service;
    } catch (error) {
      await service.close();
      throw error;
    }
  }

  get address(): AddressInfo | undefined {
    const address = this.#server.address();
    return address && typeof address !== "string" ? address : undefined;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    clearInterval(this.#cleanupTimer);
    void this.#stopListening();
    const sessions = [...this.#sessions.values()];
    const settled = await Promise.all(
      sessions.map((session) => this.#abortAndDrainForShutdown(session)),
    );
    if (settled.some((value) => !value)) {
      this.#terminateFailClosed();
      return;
    }
    await Promise.allSettled(sessions.map((session) => this.#closeSession(session.id)));
    this.#sessions.clear();
    this.#server.closeAllConnections();
    await this.#stopListening();
  }

  async #listen(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        this.#server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        this.#server.off("error", onError);
        resolve();
      };
      this.#server.once("error", onError);
      this.#server.once("listening", onListening);
      this.#server.listen(this.#port, this.#config.bindHost);
    });
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    applySecurityHeaders(response);
    try {
      if (this.#closed) {
        writeError(response, 503, "SERVER_STOPPING");
        return;
      }
      if (!hasSafePath(request)) {
        writeError(response, 404, "NOT_FOUND");
        return;
      }

      const route = request.url === "/healthz" ? "health" : "mcp";
      if (route === "health") {
        if (request.method !== "GET" || !hasSafeHealthHeaders(request)) {
          writeError(response, 405, "METHOD_NOT_ALLOWED", "GET");
          return;
        }
        drain(request);
        response.statusCode = 204;
        response.end();
        return;
      }

      if (!this.#validHostAndOrigin(request)) {
        writeError(response, 404, "NOT_FOUND");
        return;
      }

      if (request.method === "GET") {
        writeError(response, 405, "METHOD_NOT_ALLOWED", "POST, DELETE");
        return;
      }
      if (request.method !== "POST" && request.method !== "DELETE") {
        writeError(response, 405, "METHOD_NOT_ALLOWED", "POST, DELETE");
        return;
      }
      if (
        (request.method === "POST" && !hasSafePostHeaders(request)) ||
        (request.method === "DELETE" && !hasSafeDeleteHeaders(request))
      ) {
        writeError(response, 400, "REQUEST_REJECTED");
        return;
      }
      if (!this.#authorized(request)) {
        writeUnauthorized(response);
        return;
      }
      if (rawHeaderValues(request, "cookie").length > 0) {
        writeError(response, 400, "REQUEST_REJECTED");
        return;
      }

      let release: (() => void) | undefined;
      try {
        release = this.#requestAdmission.enter();
      } catch {
        writeError(response, 503, "SERVER_BUSY");
        return;
      }
      try {
        if (request.method === "DELETE") {
          await this.#handleDelete(request, response);
        } else {
          await this.#handlePost(request, response);
        }
      } finally {
        release();
      }
    } catch {
      if (!response.headersSent) writeError(response, 500, "INTERNAL_ERROR");
      else if (!response.writableEnded) response.end();
    }
  }

  async #handlePost(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let body: unknown;
    try {
      body = await readBoundedJson(request, this.#config.maxRequestBytes);
    } catch (error) {
      const code = error instanceof RemoteHttpServerError ? error.code : "REQUEST_REJECTED";
      writeError(response, code === "REQUEST_TOO_LARGE" ? 413 : 400, code);
      return;
    }

    const sessionId = readSessionId(request);
    if (sessionId === undefined && rawHeaderValues(request, "mcp-session-id").length > 0) {
      writeError(response, 400, "REQUEST_REJECTED");
      return;
    }
    const method = allowedMcpMethod(body, sessionId !== undefined);
    if (method === undefined) {
      writeError(response, 400, "REQUEST_REJECTED");
      return;
    }

    if (sessionId === undefined) {
      await this.#initializeSession(body, response);
      return;
    }

    const session = this.#sessions.get(sessionId);
    if (!session || !session.initialized) {
      writeError(response, 404, "SESSION_NOT_FOUND");
      return;
    }
    if (session.busy) {
      writeError(response, 409, "SESSION_BUSY");
      return;
    }
    if (this.#expired(session, Date.now())) {
      await this.#closeSession(session.id);
      writeError(response, 404, "SESSION_NOT_FOUND");
      return;
    }
    if (!hasExactProtocolVersion(request, session.protocolVersion)) {
      writeError(response, 400, "REQUEST_REJECTED");
      return;
    }
    if (
      (!session.clientReady && method !== "notifications/initialized") ||
      (session.clientReady && method === "notifications/initialized")
    ) {
      writeError(response, 409, "SESSION_STATE_INVALID");
      return;
    }
    if (method === "tools/call" && !isRemoteReadonlyToolCall(body)) {
      writeError(response, 403, "REMOTE_TOOL_DENIED");
      return;
    }

    session.busy = true;
    session.lastSeenAt = Date.now();
    const deadline = new RequestDeadline(this.#requestDeadlineMs);
    let transportWork: Promise<Response> | undefined;
    let transportSettled = false;
    let draining = false;
    try {
      const webRequest = toWebRequest(request, body, this.#config.publicOrigin);
      transportWork = runWithInvocationAbort(deadline.signal, () =>
        session.transport.handleRequest(webRequest, { parsedBody: body }),
      );
      this.#trackActiveRequest(session, transportWork, deadline);
      const transportResponse = await deadline.wait(transportWork);
      transportSettled = true;
      const materialized = await deadline.wait(
        materializeTransportResponse(transportResponse, {
          expectedRequestId: rpcRequestId(body),
          expectedSessionId: session.id,
          requireSessionId: method !== "notifications/initialized",
          method,
        }, deadline.signal),
      );
      deadline.close();
      emitTransportResponse(response, materialized);
      if (method === "notifications/initialized") session.clientReady = true;
      session.lastSeenAt = Date.now();
    } catch (error) {
      // Closing a JSON-response transport before its original handleRequest()
      // promise settles loses the SDK resolver. Keep this session draining,
      // abort its downstream fetches through the invocation context, and only
      // close it after the real SDK promise has settled.
      if (isRequestTimeout(error) && transportWork !== undefined && !transportSettled) {
        draining = true;
        this.#scheduleDrain(session, transportWork);
      } else {
        await this.#closeSession(session.id);
      }
      if (!response.headersSent) writeRemoteFailure(response, error);
    } finally {
      deadline.close();
      if (!draining) session.busy = false;
    }
  }

  async #initializeSession(body: unknown, response: ServerResponse): Promise<void> {
    if (
      this.#closed ||
      this.#sessions.size + this.#pendingInitializations >= this.#config.maxSessions
    ) {
      writeError(response, 503, "SERVER_BUSY");
      return;
    }
    this.#pendingInitializations += 1;

    let id: string;
    do {
      id = randomUUID();
    } while (this.#sessions.has(id) || this.#pendingSessionIds.has(id));
    this.#pendingSessionIds.add(id);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => id,
      enableJsonResponse: true,
      onsessionclosed: () => {
        this.#sessions.delete(id);
      },
    });
    let server: McpServer | undefined;
    let session: RemoteSession | undefined;
    let transportWork: Promise<Response> | undefined;
    let transportSettled = false;
    const deadline = new RequestDeadline(this.#requestDeadlineMs);
    try {
      server = this.#runtime.createMcpServer();
      await server.connect(transport);
      if (this.#closed) {
        await server.close();
        writeError(response, 503, "SERVER_STOPPING");
        return;
      }

      session = {
        id,
        server,
        transport,
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        busy: true,
        initialized: false,
        clientReady: false,
      };
      this.#sessions.set(id, session);
      const syntheticRequest = toWebRequestFromInitialize(body, this.#config.publicOrigin);
      transportWork = runWithInvocationAbort(deadline.signal, () =>
        transport.handleRequest(syntheticRequest, { parsedBody: body }),
      );
      this.#trackActiveRequest(session, transportWork, deadline);
      const transportResponse = await deadline.wait(transportWork);
      transportSettled = true;
      const initialized = await deadline.wait(
        materializeTransportResponse(transportResponse, {
          expectedRequestId: rpcRequestId(body),
          expectedSessionId: id,
          requireSessionId: true,
          requireProtocolVersion: true,
          method: "initialize",
        }, deadline.signal),
      );
      deadline.close();
      emitTransportResponse(response, initialized);
      session.initialized = true;
      session.protocolVersion = initialized.protocolVersion;
      session.lastSeenAt = Date.now();
      session.busy = false;
    } catch (error) {
      if (
        isRequestTimeout(error) &&
        session !== undefined &&
        transportWork !== undefined &&
        !transportSettled
      ) {
        this.#scheduleDrain(session, transportWork);
      } else if (session !== undefined) {
        await this.#closeSession(session.id);
      } else if (server !== undefined) {
        await server.close();
      } else {
        await transport.close();
      }
      if (!response.headersSent) writeRemoteFailure(response, error);
    } finally {
      deadline.close();
      this.#pendingSessionIds.delete(id);
      this.#pendingInitializations -= 1;
    }
  }

  async #handleDelete(request: IncomingMessage, response: ServerResponse): Promise<void> {
    drain(request);
    const sessionId = readSessionId(request);
    if (sessionId === undefined || rawHeaderValues(request, "mcp-session-id").length !== 1) {
      writeError(response, 400, "REQUEST_REJECTED");
      return;
    }
    const session = this.#sessions.get(sessionId);
    if (!session || !session.initialized) {
      writeError(response, 404, "SESSION_NOT_FOUND");
      return;
    }
    if (session.busy) {
      writeError(response, 409, "SESSION_BUSY");
      return;
    }
    if (this.#expired(session, Date.now())) {
      await this.#closeSession(session.id);
      writeError(response, 404, "SESSION_NOT_FOUND");
      return;
    }
    if (!hasExactProtocolVersion(request, session.protocolVersion)) {
      writeError(response, 400, "REQUEST_REJECTED");
      return;
    }

    session.busy = true;
    const deadline = new RequestDeadline(this.#requestDeadlineMs);
    let transportWork: Promise<Response> | undefined;
    let transportSettled = false;
    let draining = false;
    try {
      const webRequest = toWebRequest(request, undefined, this.#config.publicOrigin);
      transportWork = runWithInvocationAbort(deadline.signal, () =>
        session.transport.handleRequest(webRequest),
      );
      this.#trackActiveRequest(session, transportWork, deadline);
      const transportResponse = await deadline.wait(transportWork);
      transportSettled = true;
      const materialized = await deadline.wait(
        materializeTransportResponse(transportResponse, {}, deadline.signal),
      );
      deadline.close();
      emitTransportResponse(response, materialized);
      await this.#closeSession(session.id);
    } catch (error) {
      if (isRequestTimeout(error) && transportWork !== undefined && !transportSettled) {
        draining = true;
        this.#scheduleDrain(session, transportWork);
      } else {
        await this.#closeSession(session.id);
      }
      if (!response.headersSent) writeRemoteFailure(response, error);
    } finally {
      deadline.close();
      if (!draining) session.busy = false;
    }
  }

  async #drainTimedOutSession(
    session: RemoteSession,
    transportWork: Promise<Response>,
  ): Promise<void> {
    const result = await waitForTransportSettlement(
      transportWork,
      this.#abortSettlementGraceMs,
    );
    if (!result.settled) {
      // Do not clear/close the transport here: SDK JSON mode would discard its
      // resolver and orphan a live tool handler. Stop accepting work instead;
      // the container's supervisor must restart this fail-closed process.
      this.#enterFailClosed();
      return;
    }
    if (result.response !== undefined) cancelTransportResponse(result.response);
    this.#clearActiveRequest(session, transportWork);
    await this.#closeSession(session.id);
  }

  #scheduleDrain(session: RemoteSession, transportWork: Promise<Response>): void {
    void this.#drainTimedOutSession(session, transportWork).catch(() => {
      this.#enterFailClosed();
    });
  }

  #enterFailClosed(): void {
    if (this.#closed) return;
    this.#closed = true;
    clearInterval(this.#cleanupTimer);
    // Closing only the listener prevents any new work while preserving a
    // pending transport until the process supervisor replaces this instance.
    void this.#stopListening();
    this.#terminateFailClosed();
  }

  async #abortAndDrainForShutdown(session: RemoteSession): Promise<boolean> {
    const active = session.activeRequest;
    if (active === undefined) return true;
    active.abort();
    const result = await waitForTransportSettlement(
      active.transportWork,
      this.#abortSettlementGraceMs,
    );
    if (!result.settled) return false;
    if (result.response !== undefined) cancelTransportResponse(result.response);
    this.#clearActiveRequest(session, active.transportWork);
    return true;
  }

  #clearActiveRequest(session: RemoteSession, transportWork: Promise<Response>): void {
    if (session.activeRequest?.transportWork === transportWork) {
      session.activeRequest = undefined;
    }
  }

  #trackActiveRequest(
    session: RemoteSession,
    transportWork: Promise<Response>,
    deadline: RequestDeadline,
  ): void {
    session.activeRequest = { transportWork, abort: () => deadline.abort() };
    void transportWork.then(
      () => this.#clearActiveRequest(session, transportWork),
      () => this.#clearActiveRequest(session, transportWork),
    );
  }

  #stopListening(): Promise<void> {
    if (this.#listenerClose !== undefined) return this.#listenerClose;
    if (!this.#server.listening) return Promise.resolve();
    this.#listenerClose = new Promise((resolve) => {
      this.#server.close(() => resolve());
    });
    return this.#listenerClose;
  }

  #terminateFailClosed(): void {
    this.#fatalHandler(new Error("REMOTE_REQUEST_DID_NOT_SETTLE"));
  }

  async #closeSession(id: string): Promise<void> {
    const session = this.#sessions.get(id);
    if (!session) return;
    if (session.activeRequest !== undefined) {
      throw new RemoteHttpServerError("REQUEST_REJECTED");
    }
    this.#sessions.delete(id);
    // McpServer owns its transport after connect(); closing both would invoke
    // the SDK transport's non-idempotent close callback twice.
    await session.server.close();
  }

  async #expireIdleSessions(): Promise<void> {
    if (this.#closed) return;
    const now = Date.now();
    const expired = [...this.#sessions.values()]
      .filter((session) => !session.busy && this.#expired(session, now))
      .map((session) => session.id);
    await Promise.allSettled(expired.map((id) => this.#closeSession(id)));
  }

  #expired(session: RemoteSession, now: number): boolean {
    return (
      now - session.createdAt > this.#config.sessionMaxAgeMs ||
      now - session.lastSeenAt > this.#config.sessionIdleMs
    );
  }

  #validHostAndOrigin(request: IncomingMessage): boolean {
    const hosts = rawHeaderValues(request, "host");
    if (
      hosts.length !== 1 ||
      hosts[0]!.length > MAX_HEADER_VALUE_BYTES ||
      hosts[0]!.toLowerCase() !== this.#config.publicHost
    ) {
      return false;
    }
    const origins = rawHeaderValues(request, "origin");
    if (origins.length > 1 || (origins[0]?.length ?? 0) > MAX_HEADER_VALUE_BYTES) {
      return false;
    }
    if (origins.length === 0) return true;
    try {
      const origin = new URL(origins[0]!);
      return (
        origin.origin === this.#config.publicOrigin &&
        origin.pathname === "/" &&
        origin.search === "" &&
        origin.hash === ""
      );
    } catch {
      return false;
    }
  }

  #authorized(request: IncomingMessage): boolean {
    const authorization = rawHeaderValues(request, "authorization");
    if (authorization.length !== 1 || authorization[0]!.length > MAX_HEADER_VALUE_BYTES) {
      return false;
    }
    const match = /^Bearer ([A-Za-z0-9._~-]{32,256})$/.exec(authorization[0]!);
    if (!match?.[1]) return false;
    return this.#runtime.verifyRemoteAccessToken(match[1]);
  }
}

export class RemoteHttpServerError extends Error {
  readonly code:
    | "CONFIG_INVALID"
    | "REQUEST_REJECTED"
    | "REQUEST_TOO_LARGE"
    | "REQUEST_TIMEOUT";

  constructor(code: RemoteHttpServerError["code"]) {
    super(code);
    this.name = "RemoteHttpServerError";
    this.code = code;
  }
}

function rawHeaderValues(request: IncomingMessage, name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }
  return values;
}

function hasSafePath(request: IncomingMessage): boolean {
  return (
    request.url !== undefined &&
    request.url.length <= MAX_URL_BYTES &&
    (request.url === "/mcp" || request.url === "/healthz")
  );
}

function readSessionId(request: IncomingMessage): string | undefined {
  const values = rawHeaderValues(request, "mcp-session-id");
  if (values.length === 0) return undefined;
  if (values.length !== 1 || !SESSION_ID.test(values[0]!)) return undefined;
  return values[0]!;
}

function hasSafePostHeaders(request: IncomingMessage): boolean {
  if (rawHeaderValues(request, "content-encoding").length > 0) return false;
  if (!hasAtMostOneBoundedHeader(request, "mcp-session-id")) return false;
  if (!hasAtMostOneBoundedHeader(request, "mcp-protocol-version")) return false;
  const accept = rawHeaderValues(request, "accept");
  const contentType = rawHeaderValues(request, "content-type");
  if (
    accept.length !== 1 ||
    contentType.length !== 1 ||
    accept[0]!.length > MAX_HEADER_VALUE_BYTES ||
    contentType[0]!.length > MAX_HEADER_VALUE_BYTES ||
    !accept[0]!.includes("application/json") ||
    !accept[0]!.includes("text/event-stream") ||
    !contentType[0]!.includes("application/json")
  ) {
    return false;
  }
  const encodings = rawHeaderValues(request, "transfer-encoding");
  if (encodings.length > 1 || (encodings[0] !== undefined && encodings[0] !== "chunked")) {
    return false;
  }
  return true;
}

function hasSafeHealthHeaders(request: IncomingMessage): boolean {
  const length = rawHeaderValues(request, "content-length");
  return (
    length.length <= 1 &&
    (length[0] === undefined || length[0] === "0") &&
    rawHeaderValues(request, "transfer-encoding").length === 0 &&
    rawHeaderValues(request, "content-encoding").length === 0
  );
}

function hasSafeDeleteHeaders(request: IncomingMessage): boolean {
  if (rawHeaderValues(request, "content-encoding").length > 0) return false;
  if (!hasAtMostOneBoundedHeader(request, "mcp-session-id")) return false;
  if (!hasAtMostOneBoundedHeader(request, "mcp-protocol-version")) return false;
  const length = rawHeaderValues(request, "content-length");
  return (
    length.length <= 1 &&
    (length[0] === undefined || length[0] === "0") &&
    rawHeaderValues(request, "transfer-encoding").length === 0
  );
}

function hasAtMostOneBoundedHeader(request: IncomingMessage, name: string): boolean {
  const values = rawHeaderValues(request, name);
  return values.length <= 1 && (values[0]?.length ?? 0) <= MAX_HEADER_VALUE_BYTES;
}

function allowedMcpMethod(
  value: unknown,
  hasSession: boolean,
): SessionMethod | undefined {
  if (!isBoundedJson(value) || Array.isArray(value)) return undefined;
  if (!JSONRPCMessageSchema.safeParse(value).success) return undefined;
  if (!hasSession) {
    return InitializeRequestSchema.safeParse(value).success ? "initialize" : undefined;
  }

  const method =
    value && typeof value === "object" && "method" in value
      ? (value as { method?: unknown }).method
      : undefined;
  if (typeof method !== "string" || !ALLOWED_SESSION_METHODS.has(method)) return undefined;
  const valid = [
    InitializedNotificationSchema,
    ListToolsRequestSchema,
    CallToolRequestSchema,
    PingRequestSchema,
  ].some((schema) => schema.safeParse(value).success);
  return valid ? (method as Exclude<SessionMethod, "initialize">) : undefined;
}

function isRemoteReadonlyToolCall(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const params = (value as { params?: unknown }).params;
  if (!params || typeof params !== "object") return false;
  const name = (params as { name?: unknown }).name;
  return typeof name === "string" && REMOTE_READONLY_TOOLS.has(name);
}

function rpcRequestId(value: unknown): RpcRequestId | undefined {
  if (!value || typeof value !== "object" || !("id" in value)) return undefined;
  const id = (value as { id?: unknown }).id;
  return typeof id === "string" || (typeof id === "number" && Number.isFinite(id))
    ? id
    : undefined;
}

function hasExactProtocolVersion(
  request: IncomingMessage,
  expected: string | undefined,
): boolean {
  const values = rawHeaderValues(request, "mcp-protocol-version");
  return expected !== undefined && values.length === 1 && values[0] === expected;
}

function isBoundedJson(value: unknown, depth = 0, nodes = { count: 0 }): boolean {
  if (depth > 16 || ++nodes.count > 2_048) return false;
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return Number.isFinite(value as number) || typeof value !== "number";
  }
  if (typeof value === "string") return Buffer.byteLength(value, "utf8") <= 65_536;
  if (Array.isArray(value)) return value.every((entry) => isBoundedJson(entry, depth + 1, nodes));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value as Record<string, unknown>).every(
    ([key, entry]) =>
      Buffer.byteLength(key, "utf8") <= 256 && isBoundedJson(entry, depth + 1, nodes),
  );
}

async function readBoundedJson(request: IncomingMessage, maximum: number): Promise<unknown> {
  if (rawHeaderValues(request, "content-encoding").length > 0) {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }
  const lengths = rawHeaderValues(request, "content-length");
  if (lengths.length > 1 || (lengths[0] !== undefined && !/^\d+$/.test(lengths[0]))) {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }
  if (lengths[0] !== undefined && Number(lengths[0]) > maximum) {
    throw new RemoteHttpServerError("REQUEST_TOO_LARGE");
  }

  const content = await readBoundedRequestBody(request, maximum);

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(content);
    return JSON.parse(text) as unknown;
  } catch {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }
}

function readBoundedRequestBody(
  request: IncomingMessage,
  maximum: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let count = 0;
    let settled = false;
    let onData: (chunk: Buffer | string) => void = () => undefined;
    let onEnd: () => void = () => undefined;
    let onError: () => void = () => undefined;
    let onAborted: () => void = () => undefined;
    const cleanup = () => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: RemoteHttpServerError) => {
      if (settled) return;
      settled = true;
      cleanup();
      // The caller returns a fixed error with Connection: close. Pausing here
      // avoids draining an attacker-controlled slow/chunked body first.
      request.pause();
      reject(error);
    };
    onData = (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      count += 1;
      bytes += buffer.length;
      if (count > MAX_REQUEST_CHUNKS || bytes > maximum) {
        fail(new RemoteHttpServerError("REQUEST_TOO_LARGE"));
        return;
      }
      chunks.push(buffer);
    };
    onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks));
    };
    onError = () => fail(new RemoteHttpServerError("REQUEST_REJECTED"));
    onAborted = () => fail(new RemoteHttpServerError("REQUEST_REJECTED"));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

function toWebRequest(
  request: IncomingMessage,
  body: unknown,
  publicOrigin: string,
): Request {
  const headers = new Headers();
  for (const name of [
    "accept",
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
  ]) {
    const values = rawHeaderValues(request, name);
    if (values.length === 1) headers.set(name, values[0]!);
  }
  const method = request.method ?? "POST";
  return new Request(new URL("/mcp", publicOrigin), {
    method,
    headers,
    ...(method === "POST" ? { body: JSON.stringify(body) } : {}),
  });
}

function toWebRequestFromInitialize(body: unknown, publicOrigin: string): Request {
  return new Request(new URL("/mcp", publicOrigin), {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

async function materializeTransportResponse(
  transportResponse: Response,
  expectation: TransportResponseExpectation,
  signal: AbortSignal,
): Promise<MaterializedTransportResponse> {
  const raw = await readBoundedResponse(transportResponse, MAX_RESPONSE_BYTES, signal);
  const contentType = transportResponse.headers.get("content-type") || "";
  const status = transportResponse.status;
  const sessionId = transportResponse.headers.get("mcp-session-id");

  if (status < 200 || status >= 300 || (raw.length > 0 && !contentType.includes("application/json"))) {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }

  let parsed: unknown;
  let rendered = raw;
  let protocolVersion: string | undefined;
  if (raw.length > 0) {
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new RemoteHttpServerError("REQUEST_REJECTED");
    }
    const result = JSONRPCResultResponseSchema.safeParse(parsed);
    if (
      !result.success ||
      expectation.expectedRequestId === undefined ||
      !Object.is(result.data.id, expectation.expectedRequestId)
    ) {
      throw new RemoteHttpServerError("REQUEST_REJECTED");
    }
    if (expectation.requireProtocolVersion) {
      const candidate = result.data.result;
      if (
        !candidate ||
        typeof candidate !== "object" ||
        !("protocolVersion" in candidate) ||
        typeof (candidate as { protocolVersion?: unknown }).protocolVersion !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(
          (candidate as { protocolVersion: string }).protocolVersion,
        )
      ) {
        throw new RemoteHttpServerError("REQUEST_REJECTED");
      }
      protocolVersion = (candidate as { protocolVersion: string }).protocolVersion;
    }
    if (expectation.method === "tools/list") {
      const filtered = filterRemoteToolList(result.data);
      if (filtered === undefined) throw new RemoteHttpServerError("REQUEST_REJECTED");
      rendered = JSON.stringify(filtered);
    }
  } else if (
    expectation.expectedRequestId !== undefined ||
    (status !== 202 && status !== 200)
  ) {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }

  if (
    expectation.requireSessionId &&
    (expectation.expectedSessionId === undefined || sessionId !== expectation.expectedSessionId)
  ) {
    throw new RemoteHttpServerError("REQUEST_REJECTED");
  }

  return {
    status,
    body: rendered,
    ...(sessionId !== undefined &&
    expectation.expectedSessionId !== undefined &&
    sessionId === expectation.expectedSessionId
      ? { sessionId }
      : {}),
    ...(protocolVersion ? { protocolVersion } : {}),
  };
}

function filterRemoteToolList(response: unknown): Record<string, unknown> | undefined {
  if (!response || typeof response !== "object" || Array.isArray(response)) return undefined;
  const result = (response as { result?: unknown }).result;
  if (!result || typeof result !== "object" || Array.isArray(result)) return undefined;
  const tools = (result as { tools?: unknown }).tools;
  if (!Array.isArray(tools)) return undefined;
  const safeTools = tools.filter(
    (tool) =>
      tool &&
      typeof tool === "object" &&
      typeof (tool as { name?: unknown }).name === "string" &&
      REMOTE_READONLY_TOOLS.has((tool as { name: string }).name),
  );
  return {
    ...(response as Record<string, unknown>),
    result: {
      ...(result as Record<string, unknown>),
      tools: safeTools,
    },
  };
}

function emitTransportResponse(
  response: ServerResponse,
  materialized: MaterializedTransportResponse,
): void {
  response.statusCode = materialized.status;
  if (materialized.sessionId !== undefined) {
    response.setHeader("mcp-session-id", materialized.sessionId);
  }
  response.setHeader(
    "content-type",
    materialized.body.length > 0 ? "application/json" : "text/plain",
  );
  response.setHeader("content-length", Buffer.byteLength(materialized.body, "utf8"));
  response.end(materialized.body);
}

async function readBoundedResponse(
  response: Response,
  maximum: number,
  signal: AbortSignal,
): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let count = 0;
  const abort = () => {
    void reader.cancel();
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      count += 1;
      bytes += next.value.byteLength;
      if (count > MAX_RESPONSE_CHUNKS || bytes > maximum) {
        await reader.cancel();
        throw new RemoteHttpServerError("REQUEST_TOO_LARGE");
      }
      chunks.push(next.value);
    }
  } finally {
    signal.removeEventListener("abort", abort);
    reader.releaseLock();
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-security-policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
}

function writeUnauthorized(response: ServerResponse): void {
  response.setHeader("www-authenticate", 'Bearer realm="easypanel-mcp"');
  writeError(response, 401, "UNAUTHORIZED");
}

function writeError(
  response: ServerResponse,
  status: number,
  code: string,
  allow?: string,
): void {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    error: { code: -32000, message: code },
    id: null,
  });
  response.statusCode = status;
  response.setHeader("connection", "close");
  if (allow !== undefined) response.setHeader("allow", allow);
  response.setHeader("content-type", "application/json");
  response.setHeader("content-length", Buffer.byteLength(body, "utf8"));
  response.end(body);
}

function writeRemoteFailure(response: ServerResponse, error: unknown): void {
  if (error instanceof RemoteHttpServerError) {
    if (error.code === "REQUEST_TIMEOUT") {
      writeError(response, 504, "REQUEST_TIMEOUT");
      return;
    }
    if (error.code === "REQUEST_REJECTED" || error.code === "REQUEST_TOO_LARGE") {
      writeError(
        response,
        error.code === "REQUEST_TOO_LARGE" ? 413 : 400,
        error.code,
      );
      return;
    }
  }
  writeError(response, 500, "INTERNAL_ERROR");
}

function drain(request: IncomingMessage): void {
  request.resume();
}

function isRequestTimeout(error: unknown): error is RemoteHttpServerError {
  return error instanceof RemoteHttpServerError && error.code === "REQUEST_TIMEOUT";
}

async function waitForTransportSettlement(
  operation: Promise<Response>,
  milliseconds: number,
): Promise<{ settled: true; response?: Response } | { settled: false }> {
  return new Promise((resolve) => {
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    const finish = (result: { settled: true; response?: Response } | { settled: false }) => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) clearTimeout(timeout);
      resolve(result);
    };
    timeout = setTimeout(() => finish({ settled: false }), milliseconds);
    void operation.then(
      (response) => finish({ settled: true, response }),
      () => finish({ settled: true }),
    );
  });
}

function cancelTransportResponse(response: Response): void {
  try {
    void response.body?.cancel().catch(() => undefined);
  } catch {
    // Cancellation is only cleanup after the result is intentionally dropped.
  }
}

class RequestDeadline {
  readonly #controller = new AbortController();
  readonly #timeout: NodeJS.Timeout;

  constructor(milliseconds: number) {
    this.#timeout = setTimeout(() => this.#controller.abort(), milliseconds);
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  abort(): void {
    this.#controller.abort();
  }

  async wait<T>(operation: Promise<T>): Promise<T> {
    if (this.signal.aborted) throw new RemoteHttpServerError("REQUEST_TIMEOUT");
    let removeAbort: (() => void) | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          const onAbort = () => reject(new RemoteHttpServerError("REQUEST_TIMEOUT"));
          this.signal.addEventListener("abort", onAbort, { once: true });
          removeAbort = () => this.signal.removeEventListener("abort", onAbort);
        }),
      ]);
    } finally {
      removeAbort?.();
    }
  }

  close(): void {
    clearTimeout(this.#timeout);
  }
}
