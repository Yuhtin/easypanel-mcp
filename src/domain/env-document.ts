export class EnvDocument {
  #lines: string[];
  #values: Map<string, string>;

  private constructor(lines: string[], values: Map<string, string>) {
    this.#lines = lines;
    this.#values = values;
  }

  static parse(input: string): EnvDocument {
    if (input.includes("\u0000") || Buffer.byteLength(input, "utf8") > 1_048_576) {
      throw new TypeError("Invalid environment document");
    }
    assertBoundedLineCount(input);
    const lines = input === "" ? [] : input.replace(/\r\n?/g, "\n").split("\n");
    return new EnvDocument(lines, indexLines(lines));
  }

  clone(): EnvDocument {
    return new EnvDocument([...this.#lines], new Map(this.#values));
  }

  names(): string[] {
    return [...this.#values.keys()].sort();
  }

  entries(): Array<{ name: string; value: string }> {
    return this.names().map((name) => ({ name, value: this.#values.get(name) as string }));
  }

  get(key: string): string | undefined {
    return this.#values.get(key);
  }

  set(key: string, value: string): void {
    assertEnvKey(key);
    if (
      value.includes("\u0000") ||
      Buffer.byteLength(value, "utf8") > 65_536
    ) {
      throw new TypeError("Invalid environment variable value");
    }
    const rendered = `${key}=${encodeValue(value)}`;
    const lines = [...this.#lines];
    let replaced = false;

    for (let index = 0; index < lines.length; index += 1) {
      const assignment = parseAssignment(lines[index] ?? "");
      if (assignment?.key !== key) continue;
      if (!replaced) {
        lines[index] = rendered;
        replaced = true;
      } else {
        lines.splice(index, 1);
        index -= 1;
      }
    }

    if (!replaced) lines.push(rendered);
    this.#replaceWithValidated(lines);
  }

  remove(key: string): boolean {
    assertEnvKey(key);
    const lines = [...this.#lines];
    const before = lines.length;
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      if (parseAssignment(lines[index] ?? "")?.key === key) {
        lines.splice(index, 1);
      }
    }
    if (lines.length === before) return false;
    this.#replaceWithValidated(lines);
    return true;
  }

  serialize(): string {
    return this.#lines.join("\n");
  }

  #replaceWithValidated(lines: string[]): void {
    const serialized = lines.join("\n");
    if (Buffer.byteLength(serialized, "utf8") > 1_048_576) {
      throw new TypeError("Invalid environment document");
    }
    this.#lines = lines;
    this.#values = indexLines(lines);
  }
}

function assertBoundedLineCount(input: string): void {
  if (input === "") return;
  let lines = 1;
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code !== 0x0a && code !== 0x0d) continue;
    if (code === 0x0d && input.charCodeAt(index + 1) === 0x0a) index += 1;
    lines += 1;
    if (lines > 4_096) throw new TypeError("Invalid environment document");
  }
}

function indexLines(lines: readonly string[]): Map<string, string> {
  if (lines.length > 4_096) throw new TypeError("Invalid environment document");
  const values = new Map<string, string>();
  let assignments = 0;
  let valueBytes = 0;
  for (const line of lines) {
    if (Buffer.byteLength(line, "utf8") > 65_536) {
      throw new TypeError("Invalid environment document");
    }
    const assignment = parseAssignment(line);
    if (!assignment) continue;
    assignments += 1;
    if (assignments > 1_024) throw new TypeError("Invalid environment document");
    const previous = values.get(assignment.key);
    if (previous === undefined && values.size >= 512) {
      throw new TypeError("Invalid environment document");
    }
    if (previous !== undefined) valueBytes -= Buffer.byteLength(previous, "utf8");
    const bytes = Buffer.byteLength(assignment.value, "utf8");
    if (bytes > 65_536) throw new TypeError("Invalid environment document");
    valueBytes += bytes;
    if (valueBytes > 262_144) throw new TypeError("Invalid environment document");
    values.set(assignment.key, assignment.value);
  }
  return values;
}

function assertEnvKey(key: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new TypeError("Invalid environment variable name");
  }
}

function encodeValue(value: string): string {
  if (/^[A-Za-z0-9_./:@%+,=?&-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function decodeValue(value: string): string {
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const parsed = JSON.parse(value);
      if (typeof parsed === "string") return parsed;
    } catch {
      // Preserve malformed existing lines rather than rewriting unspecified values.
    }
  }
  return value;
}

function parseAssignment(line: string): { key: string; value: string } | null {
  const trimmed = line.trimStart();
  if (trimmed === "" || trimmed.startsWith("#")) return null;
  const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(trimmed);
  if (!match?.[1]) return null;
  return { key: match[1], value: decodeValue(match[2] ?? "") };
}
