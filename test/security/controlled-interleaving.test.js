import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, writeFile } from 'node:fs/promises';
import { runIsolatedScenario, withBoundary } from './support/controlled-interleaving.js';

test('isolated barrier preserves deterministic choreography and outside bytes', async () => {
  assert.deepEqual(await runIsolatedScenario('ordered'),
    ['subject-enter', 'interleave', 'subject-resumed']);
});

test('subject exit before checkpoint is rejected', async () => {
  await assert.rejects(runIsolatedScenario('noCheckpoint'), /Subject exited before checkpoint/);
});

test('interleaving failure propagates after the checkpoint is released', async () => {
  await assert.rejects(runIsolatedScenario('failedInterleave'), /fixture-injection-failed/);
});

test('subject failure propagates without running the interleaver', async () => {
  await assert.rejects(runIsolatedScenario('failedSubject'), /subject-failed/);
});

test('supervisor terminates a stalled subject within deadline', { timeout: 10000 }, async () => {
  const started = Date.now();
  await assert.rejects(runIsolatedScenario('hungSubject', { timeoutMs: 2000, expectedPhase: 'subject-stalled' }),
    /Isolated scenario deadline exceeded/);
  assert.ok(Date.now() - started < 8000, 'Worker shutdown exceeded the test deadline');
});

test('supervisor terminates a stalled interleaver within deadline', { timeout: 10000 }, async () => {
  const started = Date.now();
  await assert.rejects(runIsolatedScenario('hungInterleave', { timeoutMs: 2000, expectedPhase: 'interleave-stalled' }),
    /Isolated scenario deadline exceeded/);
  assert.ok(Date.now() - started < 8000, 'Worker shutdown exceeded the test deadline');
});

test('failed scenarios must still assert external file integrity before cleanup', async () => {
  await assert.rejects(runIsolatedScenario('mutatedOutsideAndFailed'), error => {
    assert.ok(error instanceof AggregateError);
    assert.match(error.errors[0].message, /scenario-invalid/);
    assert.match(error.errors[1].message, /outside file changed/);
    return true;
  });
});

test('successful callback that modifies outside file also fails integrity', async () => {
  await assert.rejects(withBoundary(async ({ outsideFile }) => {
    await writeFile(outsideFile, 'corrupted\n');
  }), /outside file changed/);
});

test('failed callback without outside effect propagates original error', async () => {
  await withBoundary(async ({ outsideFile, outsideOriginal }) => {
    assert.deepEqual(await readFile(outsideFile), outsideOriginal);
  });
  await assert.rejects(withBoundary(async () => {
    throw new Error('expected-callback-failure');
  }), /expected-callback-failure/);
});
