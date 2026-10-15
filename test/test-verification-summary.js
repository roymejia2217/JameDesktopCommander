import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';

const root = path.resolve(fileURLToPath(new URL('../', import.meta.url)));
const reporter = path.join(root, 'scripts/verification-summary-reporter.mjs');
const fixtures = path.join(root, 'test/fixtures/verification-summary');

function verifyFixture(fixture) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-reporter-'));
  const log = path.join(tmp, 'full-spec.log');
  try {
    const run = spawnSync(process.execPath, [
      '--test',
      '--test-reporter=' + pathToFileURL(reporter).href,
      '--test-reporter=spec',
      '--test-reporter-destination=stdout',
      '--test-reporter-destination=' + log,
      path.join(fixtures, fixture),
    ], {
      cwd: root,
      encoding: 'utf8',
      timeout: 20000,
      env: { ...process.env, NODE_TEST_CONTEXT: undefined, JDC_VERIFICATION_LOG_PATH: log },
    });
    assert.equal(run.error, undefined, String(run.error));
    assert.ok(fs.existsSync(log), `native spec reporter missing (status=${run.status}, stderr=${run.stderr}, stdout=${run.stdout})`);
    assert.equal(run.stdout.trim().split(/\r?\n/).length, 1,
      'console output must remain bounded to one structured summary');
    const line = run.stdout.trim();
    assert.match(line, /^VERIFICATION_SUMMARY /, `status=${run.status} stderr=${run.stderr} spec=${fs.readFileSync(log, 'utf8').slice(0,1500)}`);
    const summary = JSON.parse(line.slice('VERIFICATION_SUMMARY '.length));
    assert.equal(summary.fullLog, log);
    return { run, summary, completeLog: fs.readFileSync(log, 'utf8') };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

test('native reporter preserves all detail and a PASS summary', () => {
  const { run, summary, completeLog } = verifyFixture('passing.cjs');
  assert.equal(run.status, 0, run.stderr);
  assert.equal(summary.status, 'PASS');
  assert.equal(summary.exitCode, 0);
  assert.equal(summary.counts.tests, 1);
  assert.equal(summary.counts.passed, 1);
  assert.equal(summary.counts.failed, 0);
  assert.deepEqual(summary.failureNames, []);
  assert.ok(summary.durationMs >= 0);
  assert.match(completeLog, /NOISY_SUCCESS_FIXTURE_DETAIL/);
  assert.doesNotMatch(run.stdout, /NOISY_SUCCESS_FIXTURE_DETAIL/);
});

test('native reporter retains a failing exit and identifies failure by name', () => {
  const { run, summary, completeLog } = verifyFixture('failing.cjs');
  assert.equal(run.status, 1, run.stderr);
  assert.equal(summary.status, 'FAIL');
  assert.equal(summary.exitCode, 1);
  assert.equal(summary.counts.tests, 1);
  assert.equal(summary.counts.failed, 1);
  assert.deepEqual(summary.failureNames, ['fixture failure remains visible']);
  assert.match(completeLog, /NOISY_FAILURE_FIXTURE_DETAIL/);
  assert.match(completeLog, /intentional fixture failure/);
  assert.doesNotMatch(run.stdout, /NOISY_FAILURE_FIXTURE_DETAIL/);
});
test('missing native summary is FAIL, never a fabricated success', async () => {
  const reporter = (await import('../scripts/verification-summary-reporter.mjs')).default;
  async function* events() {
    yield { type: 'test:pass', data: { name: 'incomplete fixture' } };
  }
  const text = [];
  for await (const chunk of reporter(events())) text.push(chunk);
  const summary = JSON.parse(text.join('').trim().slice('VERIFICATION_SUMMARY '.length));
  assert.equal(summary.status, 'FAIL');
  assert.equal(summary.exitCode, 1);
  assert.equal(summary.counts, null);
});

test('failed test names are bounded and overflow is declared', async () => {
  const reporter = (await import('../scripts/verification-summary-reporter.mjs')).default;
  async function* events() {
    for (let i = 0; i < 25; i++) {
      yield { type: 'test:fail', data: { name: 'failed-' + i } };
    }
    yield { type: 'test:summary', data: {
      success: false, duration_ms: 12,
      counts: { tests: 25, passed: 0, failed: 25, skipped: 0, cancelled: 0, todo: 0 },
    } };
  }
  const text = [];
  for await (const chunk of reporter(events())) text.push(chunk);
  const summary = JSON.parse(text.join('').trim().slice('VERIFICATION_SUMMARY '.length));
  assert.equal(summary.status, 'FAIL');
  assert.equal(summary.counts.failed, 25);
  assert.equal(summary.failureNames.length, 20);
  assert.equal(summary.omittedFailureNames, 5);
  assert.equal(summary.failureNames[0], 'failed-0');
});
