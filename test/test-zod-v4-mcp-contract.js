import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { z } from 'zod';
import { toMcpInputSchema } from '../dist/tools/mcp-json-schema.js';
import {
  toolArgSchemas, ReadFileArgsSchema, EditBlockArgsSchema,
  OpenCodeTaskArgsSchema, ReadProcessOutputArgsSchema, WritePdfArgsSchema,
} from '../dist/tools/schemas.js';

const toSchema = (schema) => z.toJSONSchema(schema, {
  io: 'input',
  target: 'draft-7',
});

test('all tool argument schemas use supported native Zod 4 JSON Schema conversion', () => {
  assert.equal(typeof z.toJSONSchema, 'function', 'Zod 4 converter is required');
  assert.ok(Object.keys(toolArgSchemas).length >= 34);
  for (const [name, schema] of Object.entries(toolArgSchemas)) {
    const json = toSchema(schema);
    assert.equal(json.type, 'object', name);
    assert.ok(json.properties && typeof json.properties === 'object', name);
  }
});
test('native MCP conversion preserves security-sensitive argument shapes', () => {
  const read = toSchema(ReadFileArgsSchema);
  assert.equal(read.properties.path.type, 'string');
  assert.deepEqual(read.required, ['path']);
  assert.equal(read.properties.isUrl.type, 'boolean');
  assert.equal(read.properties.origin.enum.length, 2);

  const edit = toSchema(EditBlockArgsSchema);
  assert.equal(edit.properties.file_path.type, 'string');
  assert.ok(edit.properties.options);
  assert.ok(edit.properties.content);

  const task = toSchema(OpenCodeTaskArgsSchema);
  assert.equal(task.additionalProperties, false);
  assert.deepEqual(task.required, ['action', 'project']);
  assert.equal(task.properties.action.enum.length, 4);
  assert.equal(task.properties.timeout_ms.maximum, 1800000);

  const processOutput = toSchema(ReadProcessOutputArgsSchema);
  assert.deepEqual(processOutput.properties.wait_for.enum, ['output', 'exit']);
  assert.equal(processOutput.properties.offset.type, 'number');
});

test('advertised MCP schemas preserve closed and open object semantics', () => {
  const read = toMcpInputSchema(ReadFileArgsSchema);
  assert.equal(read.additionalProperties, false);
  assert.equal(read.properties.options.type, 'object');
  assert.notEqual(read.properties.options.additionalProperties, false);

  const pdf = toMcpInputSchema(WritePdfArgsSchema);
  assert.equal(pdf.additionalProperties, false);
  assert.equal(pdf.properties.options.additionalProperties, true);
  const insert = pdf.properties.content.anyOf[1].items.anyOf[0];
  assert.equal(insert.properties.pdfOptions.additionalProperties, true);
});

test('all 34 public MCP argument surfaces preserve the pre-migration field contract', () => {
  const contract = JSON.parse(readFileSync(
    new URL('./contracts/mcp-input-schema-zod3-baseline.json', import.meta.url),
    'utf8',
  ));
  assert.equal(Object.keys(contract).length, 34);
  for (const [name, expected] of Object.entries(contract)) {
    const source = toolArgSchemas[name];
    assert.ok(source, 'Missing schema for ' + name);
    const json = toMcpInputSchema(source);
    assert.deepEqual(Object.keys(json.properties ?? {}).sort(),
      expected.properties, name + ' properties');
    assert.deepEqual([...(json.required ?? [])].sort(),
      expected.required, name + ' required arguments');
    assert.equal(json.additionalProperties, expected.additionalProperties,
      name + ' additionalProperties');
  }
});

test('recursive JSON options remain bounded by intended JSON value types', () => {
  const json = toMcpInputSchema(ReadFileArgsSchema);
  assert.ok(json.definitions && Object.keys(json.definitions).length > 0);
  assert.deepEqual(ReadFileArgsSchema.parse({
    path: 'example.txt',
    options: { labels: ['a', 'b'], nested: { attempts: 2, active: true, blank: null } },
  }).options.nested, { attempts: 2, active: true, blank: null });
  assert.equal(ReadFileArgsSchema.safeParse({
    path: 'example.txt', options: { unsupported: () => 1 },
  }).success, false);
});

test('strict OpenCode task constraints and conditional requirements remain enforced', () => {
  assert.equal(OpenCodeTaskArgsSchema.safeParse({
    action: 'start', project: 'jamefirewall', extra: 'forbidden', prompt: 'Inspect',
  }).success, false);
  assert.equal(OpenCodeTaskArgsSchema.safeParse({
    action: 'continue', project: 'jamefirewall', prompt: 'Inspect',
  }).success, false);
  assert.equal(OpenCodeTaskArgsSchema.safeParse({
    action: 'run', project: 'jamefirewall', prompt: 'Inspect', timeout_ms: 1800001,
  }).success, false);
});

test('MCP schema normalization never changes literal default or example payloads', () => {
  const literal = {
    type: 'object',
    properties: { nested: { type: 'object' } },
    anyOf: [{ type: ['string', 'number'] }],
  };
  const schema = z.object({
    payload: z.any().default(literal).meta({ examples: [literal] }),
  });
  const raw = z.toJSONSchema(schema, { io: 'input', target: 'draft-7' });
  const converted = toMcpInputSchema(schema);
  assert.deepEqual(converted.properties.payload.default, raw.properties.payload.default);
  assert.deepEqual(converted.properties.payload.examples, raw.properties.payload.examples);
  assert.equal(converted.additionalProperties, false);
});
