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
if (process.platform === 'linux') {
  // The packaged Linux CLI intentionally exposes the user systemd lifecycle,
  // not Windows Scheduled Tasks or the Windows-only restart supervisor.
  assert.match(result.stdout, /Linux tunnel:/);
  assert.match(result.stdout, /doctor\|install --tunnel-client-bin/);
  assert.match(result.stdout, /start \| stop \| restart \| status \| uninstall/);
  assert.doesNotMatch(result.stdout, /Desktop Commander Secure MCP Tunnel lifecycle/);
  assert.doesNotMatch(result.stdout, /restart supervisor/i);
} else {
  // Preserve every original Windows help-contract assertion unchanged.
  assert.match(result.stdout, /Desktop Commander Secure MCP Tunnel lifecycle/);
  assert.match(result.stdout, /desktop-commander tunnel install/);
  assert.match(result.stdout, /desktop-commander tunnel restart/);
  assert.match(result.stdout, /desktop-commander tunnel status/);
}
assert.doesNotMatch(result.stdout, /jsonrpc/);

console.log('Platform tunnel entrypoint contract: PASS');
