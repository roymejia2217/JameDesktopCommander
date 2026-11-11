import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('edit_block occurrence verification registers executable cases', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    '--env-file=test/test.env',
    '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-edit-block-occurrences.js',
  ], { cwd: repo, env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 3 * 1024 * 1024 });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.equal(result.error, undefined, output);
  assert.equal(result.status, 0, output);
  const required = [
    'edit_block rejects too few expected matches without changing bytes',
    'edit_block rejects too many expected matches without changing bytes',
    'edit_block replaces exactly four occurrences',
    'edit_block edits header and footer without changing the middle',
    'edit_block refuses an absent pattern without changing bytes',
    'edit_block refuses an empty search without changing bytes',
  ];
  const registered = output.split(/\r?\n/)
    .filter(line => /^ok \d+ - /.test(line))
    .map(line => line.replace(/^ok \d+ - /, ''));
  assert.deepEqual(registered, required,
    `Expected six registered edit_block cases, got:\n${output}`);
  assert.match(output, /^# tests 6$/m);
  assert.match(output, /^# fail 0$/m);
});
