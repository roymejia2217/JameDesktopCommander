import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('unit verification uses Node built-in spec reporter and retains isolation flags', () => {
  const command = manifest.scripts['test:unit'];
  assert.match(command, /--test-reporter=spec(?:\s|$)/);
  assert.ok(command.includes('--env-file=test/test.env'));
  assert.ok(command.includes('--import=./test/setup-test-environment.js'));
  assert.ok(command.includes('--test-concurrency=1'));
  assert.ok(command.includes('"test/test*.js"'));
  assert.ok(!command.includes('--test-reporter-destination'));
});

test('spec reporter preserves exit failure and useful assertion diagnostics', () => {
  const fixture = fileURLToPath(new URL('./fixtures/report-failure-fixture.js', import.meta.url));
  const { NODE_TEST_CONTEXT: _testContext, ...childEnvironment } = process.env;
  const result = spawnSync(process.execPath, [
    '--test', '--test-reporter=spec', fixture,
  ], { encoding: 'utf8', timeout: 15_000, windowsHide: true, env: childEnvironment });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stdout + result.stderr, /REPORTER_ASSERTION_VISIBLE/);
  assert.match(result.stdout + result.stderr, /fail 1/);
});
