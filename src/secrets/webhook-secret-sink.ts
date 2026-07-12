import { randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { link, lstat, open, unlink, type FileHandle } from "node:fs/promises";
import { join } from "node:path";

import { ensurePrivateDirectory } from "../core/secure-path.js";
import { TargetSchema } from "../domain/schemas.js";

const RESERVED_BYTES = 8_193;

export interface WebhookSecretReservation {
  commit(value: string): Promise<void>;
  abort(): Promise<void>;
}

export interface WebhookSecretSink {
  assertReady(): Promise<void>;
  reserve(project: string, service: string): Promise<WebhookSecretReservation>;
}

export class WebhookSecretSinkError extends Error {
  readonly code = "SECRET_SINK_FAILED";

  constructor() {
    super("SECRET_SINK_FAILED");
    this.name = "WebhookSecretSinkError";
  }
}

export class FileWebhookSecretSink implements WebhookSecretSink {
  readonly #directory: string;
  #ready = false;
  #readiness?: Promise<void>;

  constructor(directory: string) {
    if (!directory || directory.includes("\u0000")) throw new WebhookSecretSinkError();
    this.#directory = directory;
  }

  async assertReady(): Promise<void> {
    if (this.#ready) return;
    const pending = this.#readiness ??= this.#probeReadiness();
    try {
      await pending;
      this.#ready = true;
    } finally {
      if (this.#readiness === pending) this.#readiness = undefined;
    }
  }

  async #probeReadiness(): Promise<void> {
    // Leading dot cannot collide with a schema-valid Easypanel project name;
    // randomness also makes concurrent readiness checks independent.
    const project = `.sink-${randomBytes(8).toString("hex")}`;
    const service = "readiness";
    const directory = await ensurePrivateDirectory(this.#directory).catch(() => {
      throw new WebhookSecretSinkError();
    });
    const destination = join(directory, `${project}--${service}.deploy-webhook`);
    const reservation = await this.#openReservation(project, service);
    try {
      await reservation.commit(`readiness-${randomBytes(16).toString("hex")}`);
      await unlink(destination);
      await syncDirectory(directory);
    } catch {
      await reservation.abort().catch(() => undefined);
      await unlink(destination).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
      throw new WebhookSecretSinkError();
    }
  }

  async reserve(
    project: string,
    service: string,
  ): Promise<WebhookSecretReservation> {
    const target = TargetSchema.safeParse({ project, service });
    if (!target.success) throw new WebhookSecretSinkError();
    return this.#openReservation(project, service);
  }

  /** Convenience for isolated sink tests; runtime rotation reserves first. */
  async store(project: string, service: string, value: string): Promise<void> {
    const reservation = await this.reserve(project, service);
    try {
      await reservation.commit(value);
    } catch (error: unknown) {
      await reservation.abort().catch(() => undefined);
      throw error;
    }
  }

  async #openReservation(
    project: string,
    service: string,
  ): Promise<WebhookSecretReservation> {
    let handle: FileHandle | undefined;
    let temporary = "";
    try {
      const directory = await ensurePrivateDirectory(this.#directory);
      const destination = join(directory, `${project}--${service}.deploy-webhook`);
      await assertDestinationAbsent(destination);
      temporary = join(
        directory,
        `.${project}--${service}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
      );
      handle = await open(
        temporary,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_RDWR |
          constants.O_NOFOLLOW,
        0o600,
      );
      const reservationBytes = Buffer.alloc(RESERVED_BYTES);
      const written = await handle.write(
        reservationBytes,
        0,
        reservationBytes.byteLength,
        0,
      );
      if (written.bytesWritten !== reservationBytes.byteLength) {
        throw new WebhookSecretSinkError();
      }
      await handle.chmod(0o600);
      assertPrivateFile(await handle.stat());
      await handle.sync();
      return new FileWebhookSecretReservation(
        directory,
        destination,
        temporary,
        handle,
      );
    } catch {
      await handle?.close().catch(() => undefined);
      if (temporary) await unlink(temporary).catch(() => undefined);
      throw new WebhookSecretSinkError();
    }
  }
}

class FileWebhookSecretReservation implements WebhookSecretReservation {
  readonly #directory: string;
  readonly #destination: string;
  readonly #temporary: string;
  readonly #handle: FileHandle;
  #finished = false;

  constructor(
    directory: string,
    destination: string,
    temporary: string,
    handle: FileHandle,
  ) {
    this.#directory = directory;
    this.#destination = destination;
    this.#temporary = temporary;
    this.#handle = handle;
  }

  async commit(value: string): Promise<void> {
    if (this.#finished || !validWebhookSecret(value)) {
      throw new WebhookSecretSinkError();
    }
    this.#finished = true;
    try {
      const content = Buffer.from(`${value}\n`, "utf8");
      const written = await this.#handle.write(content, 0, content.byteLength, 0);
      if (written.bytesWritten !== content.byteLength) throw new WebhookSecretSinkError();
      await this.#handle.truncate(content.byteLength);
      await this.#handle.chmod(0o600);
      assertPrivateFile(await this.#handle.stat());
      await this.#handle.sync();
      await this.#handle.close();
      // link(2) is an atomic no-replace publication: an existing destination
      // fails with EEXIST instead of being silently overwritten by rename(2).
      await link(this.#temporary, this.#destination);
      await unlink(this.#temporary);
      assertPrivateFile(await lstat(this.#destination));
      await syncDirectory(this.#directory);
    } catch {
      await this.#handle.close().catch(() => undefined);
      await unlink(this.#temporary).catch(() => undefined);
      throw new WebhookSecretSinkError();
    }
  }

  async abort(): Promise<void> {
    if (this.#finished) return;
    this.#finished = true;
    try {
      await this.#handle.close();
      await unlink(this.#temporary);
      await syncDirectory(this.#directory);
    } catch {
      throw new WebhookSecretSinkError();
    }
  }
}

function validWebhookSecret(value: string): boolean {
  const bytes = Buffer.byteLength(value, "utf8");
  return (
    bytes >= 16 &&
    bytes <= 8_192 &&
    !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)
  );
}

function assertPrivateFile(metadata: Stats): void {
  if (
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && metadata.uid !== process.getuid())
  ) {
    throw new WebhookSecretSinkError();
  }
}

async function assertDestinationAbsent(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error: unknown) {
    if (hasCode(error, "ENOENT")) return;
    throw new WebhookSecretSinkError();
  }
  throw new WebhookSecretSinkError();
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
