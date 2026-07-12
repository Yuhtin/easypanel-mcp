import type {
  JsonSchemaType,
  JsonSchemaValidator,
  jsonSchemaValidator,
} from "@modelcontextprotocol/sdk/validation/index.js";

/**
 * This MCP neither elicits form input nor declares structured tool outputs.
 * Supplying an explicit fail-closed provider prevents the SDK's default AJV
 * provider from being constructed or compiling a schema if a future change
 * accidentally reaches either unsupported path.
 */
class DisabledJsonSchemaValidator implements jsonSchemaValidator {
  getValidator<T>(_schema: JsonSchemaType): JsonSchemaValidator<T> {
    return () => ({
      valid: false,
      data: undefined,
      errorMessage: "VALIDATION_DISABLED",
    });
  }
}

export const disabledJsonSchemaValidator: jsonSchemaValidator = Object.freeze(
  new DisabledJsonSchemaValidator(),
);
