import assert from "node:assert/strict";
import test from "node:test";

import {
  REDACTED,
  SecretRegistry,
  redactStructure,
} from "../src/core/redaction.js";
import { EnvDocument } from "../src/domain/env-document.js";

test("redaction removes sensitive structure and registered values without mutating input", () => {
  const secret = "known secret/value+with spaces";
  const registry = new SecretRegistry();
  registry.add(secret);

  const input = {
    name: "public-name",
    authorization: `Bearer ${secret}`,
    nested: {
      database_password: secret,
      api_key: secret,
      harmless: `prefix:${secret}:suffix`,
    },
    values: [secret, { registryAuth: secret }],
  };

  const output = redactStructure(input, registry);

  assert.deepEqual(output, {
    name: "public-name",
    authorization: REDACTED,
    nested: {
      database_password: REDACTED,
      api_key: REDACTED,
      harmless: `prefix:${REDACTED}:suffix`,
    },
    values: [REDACTED, { registryAuth: REDACTED }],
  });
  assert.equal(input.nested.harmless.includes(secret), true);
  assert.equal(JSON.stringify(output).includes(secret), false);
  assert.equal(
    registry.redactText(`encoded=${encodeURIComponent(secret)}`),
    `encoded=${REDACTED}`,
  );
});

test("redaction handles circular structures without traversing them again", () => {
  const registry = new SecretRegistry();
  const value: { label: string; self?: unknown } = { label: "safe" };
  value.self = value;

  assert.deepEqual(redactStructure(value, registry), {
    label: "safe",
    self: "[CIRCULAR]",
  });
});

test("registered secrets are longest-first, ignore unsafe short values, and fail capacity closed", () => {
  const registry = new SecretRegistry({ maxValues: 2, maxBytes: 64 });
  registry.add("1");
  registry.add("short-value");
  registry.add("short-value-and-longer");
  assert.equal(
    registry.redactText("short-value-and-longer 1"),
    `${REDACTED} 1`,
  );
  assert.equal(
    registry.redactText("short-value"),
    REDACTED,
  );
  assert.throws(() => registry.add("third-secret-value"));
  assert.throws(() => new SecretRegistry().add("x".repeat(65_537)));
});

test("scoped redaction separates permanent secrets from a full valid apply working set", async () => {
  const registry = new SecretRegistry();
  const permanent = "permanent-panel-token-value";
  const existing = Array.from(
    { length: 512 },
    (_, index) => `existing-secret-${index.toString().padStart(4, "0")}`,
  );
  const replacements = Array.from(
    { length: 100 },
    (_, index) => `replacement-secret-${index.toString().padStart(4, "0")}`,
  );
  registry.add(permanent);
  registry.sealBase();

  await registry.runScoped(async () => {
    for (const value of [...existing, ...replacements]) registry.add(value);
    await Promise.resolve();
    assert.equal(
      registry.redactText(`${permanent} ${existing[511]} ${replacements[99]}`),
      `${REDACTED} ${REDACTED} ${REDACTED}`,
    );
  });

  assert.equal(registry.redactText(permanent), REDACTED);
  assert.equal(registry.redactText(existing[511] as string), existing[511]);
  assert.throws(() => registry.add("unscoped-runtime-secret"));

  for (let index = 0; index < 600; index += 1) {
    const value = `sequential-scope-secret-${index}`;
    await registry.runScoped(async () => {
      registry.add(value);
      assert.equal(registry.redactText(value), REDACTED);
    });
  }
});

test("concurrent and nested redaction scopes do not mix values or bypass quotas", async () => {
  const registry = new SecretRegistry({
    scopedMaxValues: 2,
    scopedMaxBytes: 128,
  });
  const permanent = "permanent-redaction-secret";
  const left = "left-concurrent-secret";
  const right = "right-concurrent-secret";
  registry.add(permanent);
  registry.sealBase();

  let arrivals = 0;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });
  const barrier = async (): Promise<void> => {
    arrivals += 1;
    if (arrivals === 2) release();
    await ready;
  };

  const [leftView, rightView] = await Promise.all([
    registry.runScoped(async () => {
      registry.add(left);
      await barrier();
      return registry.redactText(`${permanent} ${left} ${right}`);
    }),
    registry.runScoped(async () => {
      registry.add(right);
      await barrier();
      return registry.redactText(`${permanent} ${left} ${right}`);
    }),
  ]);
  assert.equal(leftView, `${REDACTED} ${REDACTED} ${right}`);
  assert.equal(rightView, `${REDACTED} ${left} ${REDACTED}`);

  await registry.runScoped(async () => {
    registry.add("nested-secret-one");
    await registry.runScoped(async () => {
      registry.add("nested-secret-two");
    });
    await assert.rejects(
      registry.runScoped(async () => registry.add("nested-secret-three")),
    );
  });

  await registry.runScoped(async () => registry.add("fresh-scope-after-capacity"));
});

test("late async continuations see a closed scope and cannot pollute the sealed base", async () => {
  const registry = new SecretRegistry();
  registry.add("permanent-late-test-secret");
  registry.sealBase();
  let lateAttempt!: Promise<string>;

  await assert.rejects(
    registry.runScoped(async () => {
      registry.add("scoped-secret-before-error");
      throw new Error("expected scoped failure");
    }),
  );
  assert.equal(
    registry.redactText("scoped-secret-before-error"),
    "scoped-secret-before-error",
  );

  await registry.runScoped(async () => {
    registry.add("on-time-scoped-secret");
    lateAttempt = new Promise((resolve) => {
      setTimeout(() => {
        try {
          registry.add("too-late-scoped-secret");
          resolve("unexpected-success");
        } catch (error: unknown) {
          resolve(
            error && typeof error === "object" && "code" in error
              ? String(error.code)
              : "unexpected-error",
          );
        }
      }, 0);
    });
  });

  assert.equal(await lateAttempt, "REDACTION_CAPACITY_EXCEEDED");
  assert.equal(
    registry.redactText("too-late-scoped-secret"),
    "too-late-scoped-secret",
  );
});

test("EnvDocument updates requested keys while preserving every unspecified line", () => {
  const original = [
    "# managed elsewhere",
    "UNTOUCHED=left=exactly=as-is",
    "export REPLACED=old-first",
    "REPLACED=old-second",
    "",
    "this is not an assignment",
    "REMOVE_ME=gone",
  ].join("\r\n");
  const document = EnvDocument.parse(original);

  document.set("REPLACED", "new\\value\nsecond-line");
  document.set("ADDED", "new-value");
  document.set("COMMENT_LIKE", "value # still data");
  assert.equal(document.remove("REMOVE_ME"), true);

  assert.equal(
    document.serialize(),
    [
      "# managed elsewhere",
      "UNTOUCHED=left=exactly=as-is",
      'REPLACED="new\\\\value\\nsecond-line"',
      "",
      "this is not an assignment",
      "ADDED=new-value",
      'COMMENT_LIKE="value # still data"',
    ].join("\n"),
  );
  assert.equal(document.get("UNTOUCHED"), "left=exactly=as-is");
  assert.equal(document.get("REPLACED"), "new\\value\nsecond-line");
  assert.equal(document.get("COMMENT_LIKE"), "value # still data");
  assert.deepEqual(document.names(), ["ADDED", "COMMENT_LIKE", "REPLACED", "UNTOUCHED"]);
});

test("EnvDocument clones are independent and reject invalid variable names", () => {
  const original = EnvDocument.parse("KEEP=one");
  const clone = original.clone();

  clone.set("KEEP", "two");
  assert.equal(original.serialize(), "KEEP=one");
  assert.equal(clone.serialize(), "KEEP=two");
  assert.throws(() => clone.set("BAD-NAME", "value"), TypeError);
  assert.throws(() => clone.set("VALID_NAME", "bad\u0000value"), TypeError);
  assert.throws(() => clone.remove("BAD-NAME"), TypeError);
});

test("EnvDocument indexes in one pass and rejects adversarial cardinality", () => {
  const bounded = EnvDocument.parse(
    Array.from({ length: 512 }, (_, index) => `KEY_${index}=value-${index}`).join("\n"),
  );
  assert.equal(bounded.names().length, 512);
  assert.equal(bounded.get("KEY_511"), "value-511");
  assert.throws(
    () => EnvDocument.parse(
      Array.from({ length: 513 }, (_, index) => `KEY_${index}=value-${index}`).join("\n"),
    ),
    TypeError,
  );
  assert.throws(() => EnvDocument.parse("#\n".repeat(4_096)), TypeError);
});
