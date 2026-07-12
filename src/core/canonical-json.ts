import { createHash, timingSafeEqual } from "node:crypto";

export function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalize);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([left], [right]) => compareCodePoints(left, right))
        .map(([key, entry]) => [key, normalize(entry)]),
    );
  }

  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("Cannot canonicalize a non-finite number");
  }

  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value)) ?? "null";
}

export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}
