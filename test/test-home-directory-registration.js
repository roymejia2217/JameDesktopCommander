import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('home directory suite registers six executable filesystem assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [
    '--env-file=test/test.env', '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-home-directory.js',
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
    'tilde resolves exactly to the isolated home root',
    'tilde documents path resolves inside the isolated home',
    'tilde configured root permits home files and denies outside bytes',
    'absolute home configured root grants tilde access and denies siblings',
    'tilde file operations create write read and list inside home',
    'outside-home write is denied without modifying existing bytes',
  ], output);
  assert.match(output, /^# tests 6$/m);
  assert.match(output, /^# fail 0$/m);
});
