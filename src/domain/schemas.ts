import { z } from "zod";

import { isSensitiveEnvName } from "../core/redaction.js";

export const IdentifierSchema = z
  .string()
  .min(1)
  .max(63)
  .regex(
    /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/,
    "Use lowercase letters, digits, underscores, or hyphens",
  );

export const ProjectNameSchema = IdentifierSchema.brand("ProjectName");
export const ServiceNameSchema = IdentifierSchema.brand("ServiceName");

export const SecretNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Z][A-Z0-9_]*$/, "Secret references must be uppercase env names");

export const EnvAssignmentSchema = z.discriminatedUnion("from", [
  z.object({
    from: z.literal("secret"),
    name: SecretNameSchema,
  }).strict(),
  z.object({
    from: z.literal("literal"),
    value: z.string().max(8192).refine((value) => !value.includes("\u0000")),
  }).strict(),
]);

export const EnvironmentPatchSchema = z
  .object({
    merge: z.record(
      z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).max(128),
      EnvAssignmentSchema,
    ),
    remove: z
      .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).max(128))
      .max(100)
      .default([]),
  })
  .strict()
  .superRefine((patch, context) => {
    if (Object.keys(patch.merge).length > 100) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["merge"],
        message: "At most 100 environment variables may be changed in one plan",
      });
    }
    for (const [name, assignment] of Object.entries(patch.merge)) {
      if (assignment.from === "literal" && isSensitiveEnvName(name)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["merge", name],
          message: "Sensitive variables must use a secret reference",
        });
      }
      if (patch.remove.includes(name)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["remove"],
          message: `${name} cannot be merged and removed in the same plan`,
        });
      }
    }
  });

export const SourceSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("image"),
    image: z
      .string()
      .min(1)
      .max(512)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._/:@-]*$/)
      .refine((value) => !value.includes("://"), "Registry URLs are forbidden")
      .refine(
        imageReferenceHasNoUserinfo,
        "Embedded registry credentials are forbidden",
      ),
  }).strict(),
  z.object({
    type: z.literal("git"),
    repository: z
      .string()
      .min(3)
      .max(256)
      .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Use owner/repository"),
    ref: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._\/+\-]*$/, "Use a safe ASCII Git ref")
      .refine(isSafeGitRef, "Git ref syntax is unsafe"),
    path: z
      .string()
      .min(1)
      .max(512)
      .regex(/^\/[A-Za-z0-9._\/-]*$/)
      .refine(
        (value) => value.split("/").every((segment) => segment !== "." && segment !== ".."),
        "Repository path traversal is forbidden",
      )
      .default("/"),
  }).strict(),
]);

export const ResourcesSchema = z
  .object({
    memoryReservationMb: z.number().int().min(0).max(32_768),
    memoryLimitMb: z.number().int().min(16).max(32_768),
    cpuReservation: z.number().min(0).max(32),
    cpuLimit: z.number().min(0.1).max(32),
  })
  .strict()
  .refine(
    ({ memoryReservationMb, memoryLimitMb }) =>
      memoryLimitMb >= memoryReservationMb,
    { message: "memoryLimitMb must be at least the reservation" },
  )
  .refine(
    ({ cpuReservation, cpuLimit }) => cpuLimit >= cpuReservation,
    { message: "cpuLimit must be at least the reservation" },
  );

export const DeploySettingsSchema = z
  .object({
    replicas: z.number().int().min(1).max(20),
    zeroDowntime: z.boolean().default(true),
  })
  .strict();

export const DomainSchema = z
  .object({
    host: z
      .string()
      .min(1)
      .max(253)
      .regex(
        /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/,
        "A fully-qualified lowercase hostname is required",
      ),
    port: z.number().int().min(1).max(65535),
    https: z.boolean().default(true),
  })
  .strict();

export const HealthcheckSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .max(512)
      .regex(/^\/[A-Za-z0-9._~%\/-]*$/, "Use a safe ASCII HTTP path")
      .refine((value) => !/%(?![A-Fa-f0-9]{2})/.test(value), "Invalid percent escape")
      .refine(
        (value) => value.split("/").every((segment) => segment !== "." && segment !== ".."),
        "Healthcheck path traversal is forbidden",
      )
      .refine(
        (value) => !/(?:secret|pass(?:word|wd)?|token|credential|api[-_]?key|auth)/i.test(value),
        "Healthcheck paths cannot contain credential-like material",
      ),
    port: z.number().int().min(1).max(65535),
    intervalSeconds: z.number().int().min(5).max(3600).default(30),
    timeoutSeconds: z.number().int().min(1).max(300).default(5),
  })
  .strict()
  .refine((value) => value.timeoutSeconds < value.intervalSeconds, {
    message: "Healthcheck timeout must be shorter than its interval",
  });

export const DatabaseBootstrapSchema = z
  .object({
    initialPassword: z
      .object({
        from: z.literal("secret"),
        name: SecretNameSchema,
      })
      .strict(),
  })
  .strict();

export const ServiceSpecSchema = z
  .object({
    project: ProjectNameSchema,
    service: ServiceNameSchema,
    kind: z.enum(["app", "postgres", "redis"]),
    ensure: z.enum(["present", "absent"]).default("present"),
    source: SourceSchema.optional(),
    environment: EnvironmentPatchSchema.optional(),
    resources: ResourcesSchema.optional(),
    deploy: DeploySettingsSchema.optional(),
    domains: z.array(DomainSchema).max(20).optional(),
    healthcheck: HealthcheckSchema.nullable().optional(),
    database: DatabaseBootstrapSchema.optional(),
  })
  .strict()
  .superRefine((spec, context) => {
    if (Buffer.byteLength(JSON.stringify(spec), "utf8") > 65_536) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Service specification exceeds the 64 KiB safety limit",
      });
    }
    if (spec.domains) {
      const hosts = new Set(spec.domains.map((domain) => domain.host));
      if (hosts.size !== spec.domains.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["domains"],
          message: "Domain hosts must be unique",
        });
      }
      if (spec.domains.some((domain) => !domain.https)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["domains"],
          message: "Desired domains must require HTTPS",
        });
      }
    }
    if (spec.ensure === "absent") {
      const configured = [
        spec.source,
        spec.environment,
        spec.resources,
        spec.deploy,
        spec.domains,
        spec.healthcheck,
        spec.database,
      ].some((value) => value !== undefined);
      if (configured) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "An absent service cannot also carry configuration",
        });
      }
    }

    if (spec.kind !== "app") {
      for (const field of ["source", "environment", "resources", "deploy", "domains", "healthcheck"] as const) {
        if (spec[field] !== undefined) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: [field],
            message: `${field} is only supported for app services`,
          });
        }
      }
    } else if (spec.database !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["database"],
        message: "database bootstrap settings apply only to Postgres or Redis",
      });
    }
  });

export const TargetSchema = z
  .object({
    project: ProjectNameSchema,
    service: ServiceNameSchema,
  })
  .strict();

export const ApplyInputSchema = z
  .object({
    planHash: z.string().length(64).regex(/^[a-f0-9]+$/),
  })
  .strict();

export const PlannedOperationInputSchema = TargetSchema.extend({
  planHash: z.string().length(64).regex(/^[a-f0-9]+$/).optional(),
}).strict();

export type ServiceSpec = z.infer<typeof ServiceSpecSchema>;
export type EnvironmentPatch = z.infer<typeof EnvironmentPatchSchema>;
export type EnvAssignment = z.infer<typeof EnvAssignmentSchema>;
export type ServiceSource = z.infer<typeof SourceSchema>;
export type Resources = z.infer<typeof ResourcesSchema>;
export type DeploySettings = z.infer<typeof DeploySettingsSchema>;
export type ServiceDomain = z.infer<typeof DomainSchema>;
export type Healthcheck = z.infer<typeof HealthcheckSchema>;
export type DatabaseBootstrap = z.infer<typeof DatabaseBootstrapSchema>;

function imageReferenceHasNoUserinfo(value: string): boolean {
  const at = value.indexOf("@");
  if (at === -1) return true;
  if (at !== value.lastIndexOf("@")) return false;
  const slash = value.indexOf("/");
  if (slash !== -1 && at < slash) return false;
  return /^[A-Za-z0-9._-]+:[a-fA-F0-9]{32,}$/.test(value.slice(at + 1));
}

function isSafeGitRef(value: string): boolean {
  return (
    !value.includes("..") &&
    !value.includes("//") &&
    !value.includes("@{") &&
    !value.endsWith("/") &&
    !value.endsWith(".") &&
    value.split("/").every((segment) => segment !== "." && segment !== ".." && !segment.endsWith(".lock"))
  );
}
