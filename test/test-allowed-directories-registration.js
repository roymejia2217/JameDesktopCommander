import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('allowedDirectories smoke registers six real policy assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [
    '--env-file=test/test.env', '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-allowed-directories.js',
  ], {
    cwd: repo, env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 3 * 1024 * 1024,
  });
  const output = (child.stdout ?? '') + '\n' + (child.stderr ?? '');
  assert.equal(child.error, undefined, output);
  assert.equal(child.status, 0, output);
  const names = output.split(/\r?\n/)
    .filter(line => /^ok \d+ - /.test(line))
    .map(line => line.replace(/^ok \d+ - /, ''));
  assert.deepEqual(names, [
    'empty allowlist permits both owned trees',
    'restricted root grants its children but denies sibling and home',
    'a matching directory name prefix is not an authorization',
    'trailing separator does not widen a restricted root',
    'home and tilde roots authorize the same home file only',
    'filesystem volume root grants descendants on the same volume',
  ], output);
  assert.match(output, /^# tests 6$/m);
  assert.match(output, /^# fail 0$/m);
});
