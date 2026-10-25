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
  // Traverse only JSON Schema locations that contain child schemas.
  // Metadata such as default, examples, enum and const are literal JSON data:
  // their "type", "items" or "properties" keys MUST NOT be normalized.
  for (const key of ['properties', 'patternProperties', 'definitions', '$defs']) {
    const mapping = object[key];
    if (mapping && typeof mapping === 'object' && !Array.isArray(mapping)) {
      Object.values(mapping).forEach(preserveMcpObjectContract);
    }
  }
  for (const key of [
    'additionalProperties', 'additionalItems', 'items', 'contains',
    'propertyNames', 'not', 'if', 'then', 'else', 'unevaluatedProperties',
    'unevaluatedItems',
  ]) {
    const child = object[key];
    if (Array.isArray(child)) child.forEach(preserveMcpObjectContract);
    else preserveMcpObjectContract(child);
  }
  for (const key of ['allOf', 'anyOf', 'oneOf', 'prefixItems']) {
    const children = object[key];
    if (Array.isArray(children)) children.forEach(preserveMcpObjectContract);
  }
  for (const key of ['dependencies', 'dependentSchemas']) {
    const mapping = object[key];
    if (mapping && typeof mapping === 'object' && !Array.isArray(mapping)) {
      // Draft-07 dependencies may also be string arrays, not schemas.
      Object.values(mapping).forEach(value => {
        if (!Array.isArray(value)) preserveMcpObjectContract(value);
      });
    }
  }
}

/** JSON Schema draft-07 input contract advertised by the current MCP v1 server. */
export function toMcpInputSchema(schema: z.ZodType): Record<string, unknown> {
  const json = z.toJSONSchema(schema, { io: 'input', target: 'draft-7' });
  preserveMcpObjectContract(json);
  return json;
}
