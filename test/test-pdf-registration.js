import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('PDF smoke verification registers executable assertions', () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    '--env-file=test/test.env',
    '--import=./test/setup-test-environment.js',
    '--test-reporter=tap', '--test', 'test/test-pdf-parsing.js',
  ], { cwd: repo, env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 3 * 1024 * 1024 });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.equal(result.error, undefined, output);
  assert.equal(result.status, 0, output);
  for (const name of [
    'parses local PDF fixture 01_sample_simple.pdf',
    'parses local PDF fixture 02_sample_invoice.pdf',
    'parses local PDF fixture 03_sample_compex.pdf',
    'PDF page selection returns the requested pages and bounded ranges',
    'parses a PDF fetched from a local HTTP server',
  ]) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(output, new RegExp(`^ok \\d+ - ${escaped}(?:\\s|$)`, 'm'),
      `Missing registered test: ${name}\n${output}`);
  }
  assert.match(output, /^# tests 5$/m);
  assert.match(output, /^# fail 0$/m);
});
