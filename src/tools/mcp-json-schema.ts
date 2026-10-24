import { z } from 'zod';

// Zod 4's input conversion omits additionalProperties for stripping objects,
// while the old MCP advertisement explicitly used false. Both are input
// schemas, but omission would widen what a client believes it can send.
// A bare {} at additionalProperties is equivalent to true under JSON Schema;
// spell it as true to satisfy strict MCP schema validators.
function preserveMcpObjectContract(node: unknown): void {
  if (Array.isArray(node)) {
    node.forEach(preserveMcpObjectContract);
    return;
  }
  if (node === null || typeof node !== 'object') return;
  const object = node as Record<string, unknown>;
  // Draft-07 accepts type unions, but strict Ajv (used by MCP clients)
  // rejects them unless configured specially. Express the exact same set of
  // accepted primitive values with the standard anyOf keyword instead.
  if (Array.isArray(object.type)) {
    if (Object.prototype.hasOwnProperty.call(object, 'anyOf') ||
        !object.type.every(type => typeof type === 'string')) {
      throw new TypeError('Cannot safely normalize an ambiguous JSON Schema type union');
    }
    object.anyOf = object.type.map(type => ({ type }));
    delete object.type;
  }
  if (object.type === 'object') {
    if (!Object.prototype.hasOwnProperty.call(object, 'additionalProperties')) {
      object.additionalProperties = false;
    } else if (object.additionalProperties !== null &&
        typeof object.additionalProperties === 'object' &&
        !Array.isArray(object.additionalProperties) &&
        Object.keys(object.additionalProperties).length === 0) {
      object.additionalProperties = true;
    }
  }
  Object.values(object).forEach(preserveMcpObjectContract);
}

/** JSON Schema draft-07 input contract advertised by the current MCP v1 server. */
export function toMcpInputSchema(schema: z.ZodType): Record<string, unknown> {
  const json = z.toJSONSchema(schema, { io: 'input', target: 'draft-7' });
  preserveMcpObjectContract(json);
  return json;
}
