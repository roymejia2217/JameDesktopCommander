import assert from 'node:assert/strict';
import { test } from 'node:test';

test('reporter-failure-fixture', () => {
  assert.equal(1, 2, 'REPORTER_ASSERTION_VISIBLE');
});
