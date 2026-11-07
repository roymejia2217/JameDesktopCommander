import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('blocked-command verification registers real assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    '--env-file=test/test.env',
    '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-blocked-commands.js',
  ], { cwd: repo, env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 3 * 1024 * 1024 });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.equal(result.error, undefined, output);
  assert.equal(result.status, 0, output);
  for (const name of [
    'blockedCommands rejects destructive tokens without executing them',
    'blockedCommands permits unblocked harmless commands',
    'blockedCommands changes apply immediately',
    'empty blockedCommands clears validation denials without process execution',
  ]) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(output, new RegExp(`^ok \\d+ - ${escaped}(?:\\s|$)`, 'm'),
      `Missing registered test: ${name}\n${output}`);
  }
  assert.match(output, /^# tests 4$/m);
  assert.match(output, /^# fail 0$/m);
});
