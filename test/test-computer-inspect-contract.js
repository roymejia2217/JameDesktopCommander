#!/usr/bin/env node

import assert from 'node:assert/strict';
import { ComputerInspectArgsSchema } from '../dist/tools/schemas.js';

const health = ComputerInspectArgsSchema.safeParse({ action: 'health' });
assert.equal(health.success, true, 'health request should be valid');

const snapshot = ComputerInspectArgsSchema.safeParse({
  action: 'snapshot',
  maxDepth: 8,
  maxElements: 500,
  includeScreenshot: true,
  screenshotMaxWidth: 1920,
});
assert.equal(snapshot.success, true, 'bounded snapshot request should be valid');

for (const invalid of [
  { action: 'snapshot', maxDepth: 0 },
  { action: 'snapshot', maxDepth: 9 },
  { action: 'snapshot', maxElements: 0 },
  { action: 'snapshot', maxElements: 501 },
  { action: 'snapshot', screenshotMaxWidth: 319 },
  { action: 'snapshot', screenshotMaxWidth: 1921 },
  { action: 'click' },
]) {
  assert.equal(
    ComputerInspectArgsSchema.safeParse(invalid).success,
    false,
    'unsafe or unsupported computer inspection input must be rejected',
  );
}

console.log('Computer inspect schema contract test passed');
