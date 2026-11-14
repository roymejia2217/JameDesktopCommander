import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('REPL interaction registers four executable terminal lifecycle cases', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, [
    '--env-file=test/test.env', '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-repl-interaction.js',
  ], {
    cwd: repo, env, encoding: 'utf8', timeout: 90_000,
    maxBuffer: 3 * 1024 * 1024,
  });
  const output = (child.stdout ?? '') + '\n' + (child.stderr ?? '');
  assert.equal(child.error, undefined, output);
  assert.equal(child.status, 0, output);
  const lines = output.split(/\r?\n/);
  const named = lines.filter(line => /^ok \d+ - /.test(line));
  const skipped = named.filter(line => / # SKIP(?: |$)/.test(line));
  assert.ok(skipped.length <= 1, 'only Python availability may be skipped: ' + output);
  if (skipped.length === 1) {
    assert.match(skipped[0], /^ok 3 - Python REPL evaluates stdin when interpreter is installed # SKIP No usable Python 3 interpreter is installed on this host$/);
  }
  const names = named.map(line => line.replace(/^ok \d+ - /, '').replace(/ # SKIP.*$/, ''));
  assert.deepEqual(names, [
    'Node REPL computes a deterministic value from stdin',
    'Node REPL accepts sequential input without losing output',
    'Python REPL evaluates stdin when interpreter is installed',
    'Node REPL propagates nonzero exit and rejects further stdin',
  ], output);
  assert.match(output, /^# tests 4$/m);
  assert.match(output, /^# fail 0$/m);
});