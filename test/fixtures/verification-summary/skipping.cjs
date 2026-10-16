const { test } = require('node:test');

test.skip('fixture intentionally omitted', 'platform-specific capability', () => {
  throw new Error('skipped fixture must never execute');
});
