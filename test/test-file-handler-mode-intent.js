import assert from 'node:assert/strict';
import { test } from 'node:test';
import runFileHandlerTests from './test-file-handlers.js';

// Exercise real files through the MCP handler, including inherited-mode
// rejection, explicit append/rewrite, and the missing-mode compatibility path.
test('file handler preserves content unless write mode is explicitly owned',
  { timeout: 30_000 }, async () => {
    assert.equal(await runFileHandlerTests(), true);
  });
