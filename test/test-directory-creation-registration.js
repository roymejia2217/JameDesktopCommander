import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('directory creation registers six executable policy assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [
    '--env-file=test/test.env', '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-directory-creation.js',
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
    'creates directory under an existing permitted parent',
    'creates intermediate parents recursively inside the permitted root',
    'repeated directory creation preserves existing file bytes',
    'restricted root denies an outside directory and preserves its sentinel',
    'prefix-collision sibling is denied without side effects',
    'empty allowlist permits creation in a separate owned subtree',
  ], output);
  assert.match(output, /^# tests 6$/m);
  assert.match(output, /^# fail 0$/m);
});
