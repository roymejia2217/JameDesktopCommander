import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('default-shell verification registers real node:test cases', () => {
  // The nested invocation must be a standalone test runner, not inherit the
  // outer node:test worker context (which suppresses recursive discovery).
  const childEnv = { ...process.env };
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [
    '--env-file=test/test.env',
    '--import=./test/setup-test-environment.js',
    '--test',
    'test/test-default-shell.js',
  ], { cwd: repo, env: childEnv, encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 * 1024 });
  const output = `${child.stdout ?? ''}\n${child.stderr ?? ''}`;
  assert.equal(child.error, undefined, output);
  assert.equal(child.status, 0, output);
  for (const name of [
    'default shell selects /bin/sh',
    'default shell selects /bin/bash',
    'default shell selects cmd',
    'default shell selects PowerShell Core',
    'default shell switching changes the executing shell',
    'default shell configuration persists',
    'delayed shell output is read after the process exits',
  ]) {
    assert.ok(output.includes(name),
      `The runner did not register the scenario: ${name}\n${output}`);
  }
});
