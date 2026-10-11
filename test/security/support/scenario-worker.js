import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { parentPort, workerData } from 'node:worker_threads';
import { controlledInterleaving } from './controlled-interleaving.js';

const { scenario, fixture } = workerData;
const scenarios = {
  async ordered() {
    const events = [];
    await controlledInterleaving({
      subject: async checkpoint => {
        events.push('subject-enter');
        await checkpoint();
        events.push('subject-resumed');
        assert.equal(await readFile(fixture.insideFile, 'utf8'), 'in-root-update\n');
      },
      interleave: async () => {
        events.push('interleave');
        await writeFile(fixture.insideFile, 'in-root-update\n');
      },
    });
    return events;
  },
  async noCheckpoint() {
    return controlledInterleaving({ subject: async () => {}, interleave: async () => {} });
  },
  async failedInterleave() {
    let released = false;
    try {
      await controlledInterleaving({
        subject: async checkpoint => { await checkpoint(); released = true; },
        interleave: async () => { throw new Error('fixture-injection-failed'); },
      });
    } catch (error) {
      assert.equal(released, true, 'Checkpoint was not released on failure');
      throw error;
    }
  },
  async failedSubject() {
    let interleaveRan = false;
    try {
      await controlledInterleaving({
        subject: async () => { throw new Error('subject-failed'); },
        interleave: async () => { interleaveRan = true; },
      });
    } catch (error) {
      assert.equal(interleaveRan, false);
      throw error;
    }
  },
  async hungSubject() {
    await controlledInterleaving({
      subject: async checkpoint => {
        await checkpoint();
        parentPort.postMessage({ phase: 'subject-stalled' });
        await new Promise(() => { setInterval(() => {}, 1000); });
      },
      interleave: async () => {},
    });
  },
  async hungInterleave() {
    await controlledInterleaving({
      subject: async checkpoint => { await checkpoint(); },
      interleave: async () => {
        parentPort.postMessage({ phase: 'interleave-stalled' });
        await new Promise(() => { setInterval(() => {}, 1000); });
      },
    });
  },
  async mutatedOutsideAndFailed() {
    await writeFile(fixture.outsideFile, 'corrupted\n');
    throw new Error('scenario-invalid');
  },
};
try {
  if (!Object.hasOwn(scenarios, scenario)) throw new Error('Unknown test-only scenario');
  const value = await scenarios[scenario]();
  parentPort.postMessage({ ok: true, value });
} catch (error) {
  parentPort.postMessage({ ok: false, error: {
    name: error instanceof Error ? error.name : 'Error',
    message: error instanceof Error ? error.message : String(error),
  } });
}
