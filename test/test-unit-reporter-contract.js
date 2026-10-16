import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('unit verification keeps the full native spec log and a bounded stdout summary', () => {
  const command = manifest.scripts['test:unit'];
  assert.match(command, /--test-reporter=\.\/scripts\/verification-summary-reporter\.mjs(?:\s|$)/);
  assert.match(command, /--test-reporter=spec(?:\s|$)/);
  assert.match(command, /--test-reporter-destination=stdout(?:\s|$)/);
  assert.match(command, /--test-reporter-destination=\.tmp\/verification\/unit-spec\.log(?:\s|$)/);
  assert.equal((command.match(/--test-reporter=/g) ?? []).length, 2,
    'exactly two native reporters are required');
  assert.equal((command.match(/--test-reporter-destination=/g) ?? []).length, 2,
    'each reporter requires its own destination');
  assert.ok(command.includes('--env-file=test/test.env'));
  assert.ok(command.includes('--import=./test/setup-test-environment.js'));
  assert.ok(command.includes('--test-concurrency=1'));
  assert.ok(command.includes('"test/test*.js"'));
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
