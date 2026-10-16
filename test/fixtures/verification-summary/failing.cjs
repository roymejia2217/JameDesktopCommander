const { test } = require('node:test');
const assert = require('node:assert/strict');
test('fixture failure remains visible', () => {
  console.log('NOISY_FAILURE_FIXTURE_DETAIL');
  assert.equal(1, 2, 'intentional fixture failure');
});
