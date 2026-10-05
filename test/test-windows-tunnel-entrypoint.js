import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.resolve(testDirectory, '..', 'dist', 'index.js');
const result = spawnSync(
  process.execPath,
  [entrypoint, 'tunnel', '--help'],
  {
    encoding: 'utf8',
    timeout: 10_000,
    windowsHide: true,
  },
);

assert.equal(result.error, undefined);
assert.equal(result.status, 0, result.stderr);
assert.match(result.stdout, /Desktop Commander Secure MCP Tunnel lifecycle/);
assert.match(result.stdout, /desktop-commander tunnel install/);
assert.doesNotMatch(result.stdout, /jsonrpc/);

console.log('Windows tunnel entrypoint contract: PASS');
