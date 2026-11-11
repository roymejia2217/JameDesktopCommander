import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('basic edit smoke registers four real node:test assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    '--env-file=test/test.env', '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test.js',
  ], {
    cwd: repo, env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 3 * 1024 * 1024,
  });
  const output = (result.stdout ?? '') + '\n' + (result.stderr ?? '');
  assert.equal(result.error, undefined, output);
  assert.equal(result.status, 0, output);
  const names = output.split(/\r?\n/)
    .filter(line => /^ok \d+ - /.test(line))
    .map(line => line.replace(/^ok \d+ - /, ''));
  assert.deepEqual(names, [
    'basic edit replaces a single exact substring and preserves surrounding bytes',
    'basic edit does not write when the substring is absent',
    'basic edit does not write when the expected replacement count is wrong',
    'basic edit denies an outside-root file and preserves its bytes',
  ], output);
  assert.match(output, /^# tests 4$/m);
  assert.match(output, /^# fail 0$/m);
});
