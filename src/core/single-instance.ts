import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync, unlinkSync } from "node:fs";
import { open, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { ensurePrivateDirectory } from "./secure-path.js";

export class SingleInstanceError extends Error {
  readonly code: "INSTANCE_ALREADY_RUNNING" | "INSTANCE_LOCK_FAILED";

  constructor(code: SingleInstanceError["code"]) {
    super(code);
    this.name = "SingleInstanceError";
    this.code = code;
  }
}

export class SingleInstanceLock {
  readonly #path: string;
  readonly #content: string;
  readonly #onExit: () => void;
  #released = false;

  private constructor(path: string, content: string) {
    this.#path = path;
    this.#content = content;
    this.#onExit = () => this.#releaseSync();
    process.once("exit", this.#onExit);
  }

  static async acquire(inputPath: string): Promise<SingleInstanceLock> {
    const filename = basename(inputPath);
    if (!inputPath || inputPath.includes("\u0000") || filename === "." || filename === "..") {
      throw new SingleInstanceError("INSTANCE_LOCK_FAILED");
    }

    try {
      const directory = await ensurePrivateDirectory(dirname(inputPath));
      const path = join(directory, filename);
      const content = `${process.pid}:${randomBytes(24).toString("hex")}\n`;
      const handle = await open(
        path,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_WRONLY |
          constants.O_NOFOLLOW,
        0o600,
      );
      try {
        const written = await handle.write(content, null, "utf8");
        if (written.bytesWritten !== Buffer.byteLength(content, "utf8")) {
          throw new SingleInstanceError("INSTANCE_LOCK_FAILED");
        }
        await handle.chmod(0o600);
        const metadata = await handle.stat();
        if (
          !metadata.isFile() ||
          metadata.nlink !== 1 ||
          (typeof process.getuid === "function" && metadata.uid !== process.getuid()) ||
          (metadata.mode & 0o077) !== 0
        ) {
          throw new SingleInstanceError("INSTANCE_LOCK_FAILED");
        }
        await handle.sync();
      } finally {
        await handle.close();
      }
      return new SingleInstanceLock(path, content);
    } catch (error: unknown) {
      if (hasCode(error, "EEXIST")) {
        throw new SingleInstanceError("INSTANCE_ALREADY_RUNNING");
      }
      if (error instanceof SingleInstanceError) throw error;
      throw new SingleInstanceError("INSTANCE_LOCK_FAILED");
    }
  }

  async release(): Promise<void> {
    if (this.#released) return;
    try {
      if (await this.#ownsLock()) await unlink(this.#path);
      this.#released = true;
      process.off("exit", this.#onExit);
    } catch {
      throw new SingleInstanceError("INSTANCE_LOCK_FAILED");
    }
  }

  async #ownsLock(): Promise<boolean> {
    const handle = await open(this.#path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile() || metadata.nlink !== 1 || metadata.size > 128) return false;
      return (await handle.readFile("utf8")) === this.#content;
    } finally {
      await handle.close();
    }
  }

  #releaseSync(): void {
    if (this.#released) return;
    this.#released = true;
    let descriptor: number | undefined;
    try {
      descriptor = openSync(this.#path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const metadata = fstatSync(descriptor);
      if (
        metadata.isFile() &&
        metadata.nlink === 1 &&
        metadata.size <= 128 &&
        readFileSync(descriptor, "utf8") === this.#content
      ) {
        unlinkSync(this.#path);
      }
    } catch {
      // Exit cleanup is best effort. A stale lock fails closed on next startup.
    } finally {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          // Process exit has no safe recovery path.
        }
      }
    }
  }
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
