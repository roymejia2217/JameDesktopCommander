import assert from 'node:assert/strict';
import { test } from 'node:test';
import { z } from 'zod';
import {
  detectUnsupportedParams,
  getSupportedParams,
} from '../dist/utils/unsupportedParams.js';

test('Zod 4 tool object reports unsupported top-level arguments', () => {
  const schema = z.object({
    path: z.string(),
    offset: z.number().optional(),
    length: z.number().optional(),
  });
  assert.deepEqual(getSupportedParams(schema), ['path', 'offset', 'length']);
  assert.deepEqual(
    detectUnsupportedParams({ path: 'fixture', view_range: [2, 4], foo_bar: true }, schema),
    ['view_range', 'foo_bar'],
  );
  assert.deepEqual(detectUnsupportedParams({ path: 'fixture' }, schema), []);
});
test('wrapped Zod 4 objects retain supported-parameter detection', () => {
  const schema = z.object({ path: z.string() }).optional().default({ path: 'fixture' });
  assert.deepEqual(getSupportedParams(schema), ['path']);
  assert.deepEqual(detectUnsupportedParams({ path: 'fixture', bad: true }, schema), ['bad']);
  assert.deepEqual(detectUnsupportedParams({ arbitrary: true }, z.string()), []);
});
