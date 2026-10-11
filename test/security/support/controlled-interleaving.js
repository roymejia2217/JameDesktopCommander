import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';

// Cooperative barrier; security scenarios MUST run in a supervised Worker.
// Arbitrary in-process promises cannot be forcibly cancelled on timeout.
export async function controlledInterleaving({ subject, interleave }) {
  let enter, release;
  const entered = new Promise(resolve => { enter = resolve; });
  const released = new Promise(resolve => { release = resolve; });
  let used = false;
  const checkpoint = async () => {
    assert.equal(used, false, 'Checkpoint must be reached exactly once');
    used = true;
    enter();
    await released;
  };
  const operation = Promise.resolve().then(() => subject(checkpoint));
  const completed = operation.then(() => {
    if (!used) throw new Error('Subject exited before checkpoint');
  });
  try {
    await Promise.race([entered, completed]);
    assert.equal(used, true, 'Subject did not enter checkpoint');
    await interleave();
    release();
    await completed;
  } finally {
    release();
    // Worker termination bounds this wait if a scenario stalls.
    await operation.catch(() => {});
  }
}

export async function withBoundary(callback) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-security-boundary-'));
  try {
    const inside = join(root, 'inside');
    const outside = join(root, 'outside');
    await Promise.all([mkdir(inside), mkdir(outside)]);
    const insideFile = join(inside, 'fixture.txt');
    const outsideFile = join(outside, 'sentinel.txt');
    const insideOriginal = Buffer.from('authorized fixture\n');
    const outsideOriginal = Buffer.from('outside sentinel\n');
    await Promise.all([writeFile(insideFile, insideOriginal), writeFile(outsideFile, outsideOriginal)]);
    let value;
    let failure;
    try {
      value = await callback({ insideFile, outsideFile, insideOriginal, outsideOriginal });
    } catch (error) {
      failure = error;
    }
    let integrityFailure;
    try {
      assert.deepEqual(await readFile(outsideFile), outsideOriginal,
        'An unrelated outside file changed during a controlled fixture test');
    } catch (error) {
      integrityFailure = error;
    }
    if (failure && integrityFailure) {
      throw new AggregateError([failure, integrityFailure],
        'Scenario failed and outside fixture integrity was violated');
    }
    if (integrityFailure) throw integrityFailure;
    if (failure) throw failure;
    return value;
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

// Run arbitrary test scenarios in a terminable worker; the parent owns all
// fixture paths and checks their bytes only after the worker has exited.
export async function runIsolatedScenario(scenario, { timeoutMs = 10000, expectedPhase } = {}) {
  assert.match(scenario, /^[a-zA-Z][a-zA-Z0-9]*$/);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 60000);
  return withBoundary(async fixture => {
    const worker = new Worker(new URL('./scenario-worker.js', import.meta.url), {
      workerData: { scenario, fixture: { insideFile: fixture.insideFile,
        outsideFile: fixture.outsideFile } },
    });
    let timer;
    let phaseReached = false;
    try {
      return await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(expectedPhase && !phaseReached
          ? 'Scenario never reached expected checkpoint' : 'Isolated scenario deadline exceeded')), timeoutMs);
        worker.on('message', message => {
          if (message.phase) {
            if (message.phase === expectedPhase) phaseReached = true;
            return;
          }
          if (message.ok) resolve(message.value);
          else reject(Object.assign(new Error(message.error.message), { name: message.error.name }));
        });
        worker.once('error', reject);
        worker.once('exit', code => reject(new Error('Scenario worker exited without a result: ' + code)));
      });
    } finally {
      clearTimeout(timer);
      await worker.terminate(); // Always await termination before fixture integrity/cleanup.
    }
  });
}
