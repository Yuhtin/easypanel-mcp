import { spawn } from "node:child_process";
import { readdir, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function run(command, arguments_, environment) {
  return new Promise((resolve) => {
    const child = spawn(command, arguments_, {
      env: environment,
      stdio: "inherit",
    });
    child.once("error", () => resolve(1));
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

const buildExitCode = await run(
  process.execPath,
  ["node_modules/typescript/bin/tsc", "-p", "tsconfig.test.json"],
  process.env,
);
if (buildExitCode !== 0) {
  process.exitCode = buildExitCode;
} else {
  const environment = { ...process.env };
  // macOS commonly exposes /var through an OS-owned symlink to /private/var.
  // Security tests intentionally reject symlinked state paths, so make only
  // their temporary root canonical rather than weakening that invariant.
  if (process.platform !== "win32") {
    try {
      environment.TMPDIR = await realpath(tmpdir());
    } catch {
      // Keep the platform default if its temp root cannot be canonicalized.
    }
  }
  const tests = (await readdir(".test-dist/test"))
    .filter((entry) => entry.endsWith(".test.js"))
    .sort()
    .map((entry) => join(".test-dist/test", entry));
  process.exitCode = await run(
    process.execPath,
    ["--test", "--test-concurrency=1", ...tests],
    environment,
  );
}
