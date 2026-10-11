import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, writeFile } from 'node:fs/promises';
import { controlledInterleaving, withBoundary } from './support/controlled-interleaving.js';

test('barrier makes an allowed in-root mutation deterministic and preserves outside bytes', async () => {
  await withBoundary(async ({ insideFile, outsideFile, insideOriginal, outsideOriginal }) => {
    const observed = [];
    await controlledInterleaving({
      subject: async checkpoint => {
        observed.push('subject-enter');
        assert.deepEqual(await readFile(insideFile), insideOriginal);
        await checkpoint();
        observed.push('subject-resumed');
        assert.equal(await readFile(insideFile, 'utf8'), 'in-root-update\n');
      },
      interleave: async () => {
        observed.push('interleave');
        await writeFile(insideFile, 'in-root-update\n');
      },
    });
    assert.deepEqual(observed, ['subject-enter', 'interleave', 'subject-resumed']);
    assert.deepEqual(await readFile(outsideFile), outsideOriginal);
  });
});

test('a subject that never reaches the checkpoint fails explicitly', async () => {
  await assert.rejects(
    controlledInterleaving({ subject: async () => {}, interleave: async () => {} }),
    /Subject exited before checkpoint/
  );
});

test('interleaving errors release the checkpoint and are not hidden', async () => {
  let released = false;
  await assert.rejects(controlledInterleaving({
    subject: async checkpoint => { await checkpoint(); released = true; },
    interleave: async () => { throw new Error('fixture-injection-failed'); },
  }), /fixture-injection-failed/);
  assert.equal(released, true, 'Barrier left the worker blocked after fixture failure');
});

test('a subject failure before the barrier propagates without running interleaver', async () => {
  let mutated = false;
  await assert.rejects(controlledInterleaving({
    subject: async () => { throw new Error('subject-failed'); },
    interleave: async () => { mutated = true; },
  }), /subject-failed/);
  assert.equal(mutated, false);
});
