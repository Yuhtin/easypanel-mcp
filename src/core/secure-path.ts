import { constants, type Stats } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { isAbsolute, parse, relative, resolve, sep } from "node:path";

export async function ensurePrivateDirectory(input: string): Promise<string> {
  if (!input || input.includes("\u0000")) throw new Error("SECURE_PATH_INVALID");
  const absolute = isAbsolute(input) ? resolve(input) : resolve(process.cwd(), input);
  const root = parse(absolute).root;
  if (absolute === root || absolute === resolve(process.cwd())) {
    throw new Error("SECURE_PATH_INVALID");
  }
  const parts = relative(root, absolute).split(sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = resolve(current, part);
    let metadata: Stats;
    try {
      metadata = await lstat(current);
    } catch (error: unknown) {
      if (!hasCode(error, "ENOENT")) throw error;
      // Create one component at a time. Recursive mkdir would follow an
      // attacker-controlled intermediate symlink before we could reject it.
      await mkdir(current, { mode: 0o700 });
      metadata = await lstat(current);
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error("SECURE_PATH_INVALID");
    }
  }

  const handle = await open(
    absolute,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat();
    if (
      !before.isDirectory() ||
      (typeof process.getuid === "function" && before.uid !== process.getuid())
    ) {
      throw new Error("SECURE_PATH_INVALID");
    }
    await handle.chmod(0o700);
    const after = await handle.stat();
    if ((after.mode & 0o077) !== 0) throw new Error("SECURE_PATH_INVALID");
  } finally {
    await handle.close();
  }
  return absolute;
}

function hasCode(error: unknown, code: string): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}
