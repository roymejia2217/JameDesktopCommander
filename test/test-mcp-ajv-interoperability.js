import assert from 'node:assert/strict';
import { test } from 'node:test';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { toolArgSchemas } from '../dist/tools/schemas.js';
import { toMcpInputSchema } from '../dist/tools/mcp-json-schema.js';

function inspectorCompatibleAjv() {
  const validator = new Ajv({ strict: true, allErrors: true });
  addFormats(validator);
  return validator;
}

test('every registered MCP input schema compiles in strict draft-07 Ajv', () => {
  const ajv = inspectorCompatibleAjv();
  const names = Object.keys(toolArgSchemas);
  assert.ok(names.length >= 34, 'The complete tool schema registry is required');
  for (const name of names) {
    const jsonSchema = toMcpInputSchema(toolArgSchemas[name]);
    assert.doesNotThrow(() => ajv.compile(jsonSchema), name);
  }
});
test('MCP draft-07 clients validate nested JSON options and preserve closed roots', () => {
  const ajv = inspectorCompatibleAjv();
  const read = ajv.compile(toMcpInputSchema(toolArgSchemas.read_file));
  assert.equal(read({
    path: 'report.txt',
    options: { nested: { enabled: true, tags: ['first', null, 3] } },
  }), true, JSON.stringify(read.errors));
  assert.equal(read({ path: 'report.txt', unexpected: 'not a tool argument' }), false);
  assert.equal(read({ path: 'report.txt', options: { unsafe: { nested: [1, {}] } } }), true,
    JSON.stringify(read.errors));

  const edit = ajv.compile(toMcpInputSchema(toolArgSchemas.edit_block));
  assert.equal(edit({
    file_path: 'example.xlsx',
    range: 'Sheet1!A1:B2',
    content: [{ rich: { text: 'value' } }, [true, null, 3]],
  }), true, JSON.stringify(edit.errors));
});
test('MCP draft-07 clients reject invalid security-relevant constraints', () => {
  const ajv = inspectorCompatibleAjv();
  const probe = ajv.compile(toMcpInputSchema(toolArgSchemas.tunnel_probe));
  assert.equal(probe({ challenge: 'a'.repeat(32) }), true);
  assert.equal(probe({ challenge: 'A'.repeat(32) }), false);
  assert.equal(probe({ challenge: 'a'.repeat(32), override: true }), false);

  const task = ajv.compile(toMcpInputSchema(toolArgSchemas.opencode_task));
  assert.equal(task({ action: 'run', project: 'jamefirewall', prompt: 'Inspect' }), true);
  assert.equal(task({ action: 'run', project: 'jamefirewall', prompt: 'Inspect', extra: true }), false);
  assert.equal(task({ action: 'run', project: 'jamefirewall', prompt: 'Inspect', timeout_ms: 1800001 }), false);
});

test('UI telemetry values remain the original scalar-only union in strict Ajv', () => {
  const ajv = inspectorCompatibleAjv();
  const schema = toMcpInputSchema(toolArgSchemas.track_ui_event);
  const scalar = schema.properties.params.additionalProperties;
  assert.ok(Array.isArray(scalar.anyOf), 'Standard anyOf union required');
  assert.deepEqual(scalar.anyOf.map(v => v.type).sort(),
    ['boolean', 'null', 'number', 'string']);
  const validate = ajv.compile(schema);
  assert.equal(validate({
    event: 'preview_loaded',
    params: { mode: 'file', count: 2, visible: true, blank: null },
  }), true, JSON.stringify(validate.errors));
  assert.equal(validate({ event: 'preview_loaded', params: { nested: {} } }), false);
});
