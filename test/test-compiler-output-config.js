import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

test('normal JDC TypeScript builds do not enumerate every emitted artifact', async () => {
  const config = JSON.parse(await readFile(new URL('../tsconfig.json', import.meta.url), 'utf8'));
  assert.equal(config.compilerOptions.listEmittedFiles, false,
    'normal CI and developer builds should be quiet unless explicitly diagnosed');
});

test('TypeScript diagnostics and declaration emission stay configured', async () => {
  const config = JSON.parse(await readFile(new URL('../tsconfig.json', import.meta.url), 'utf8'));
  assert.equal(config.compilerOptions.declaration, true);
  assert.equal(config.compilerOptions.diagnostics, true);
  assert.equal(config.compilerOptions.extendedDiagnostics, true);
});
