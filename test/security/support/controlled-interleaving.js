import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// A barrier independent of JDC implementations and production host services.
export async function controlledInterleaving({ subject, interleave, timeoutMs = 10000 }) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 60000);
  let signalEntered, signalRelease;
  const entered = new Promise(resolve => { signalEntered = resolve; });
  const released = new Promise(resolve => { signalRelease = resolve; });
  let used = false;
  const checkpoint = async () => {
    assert.equal(used, false, 'Checkpoint must be reached exactly once');
    used = true;
    signalEntered();
    await released;
  };
  const deadline = AbortSignal.timeout(timeoutMs);
  let rejectTimeout;
  const timedOut = new Promise((_, reject) => { rejectTimeout = reject; });
  const onTimeout = () => rejectTimeout(new Error('Controlled interleaving deadline exceeded'));
  deadline.addEventListener('abort', onTimeout, { once: true });
  const operation = Promise.resolve().then(() => subject(checkpoint));
  const completed = operation.then(() => { if (!used) throw new Error('Subject exited before checkpoint'); });
  try {
    await Promise.race([entered, completed, timedOut]);
    assert.equal(used, true, 'Subject did not enter the checkpoint');
    await Promise.race([Promise.resolve().then(interleave), timedOut]);
    signalRelease();
    return await Promise.race([completed, timedOut]);
  } finally {
    signalRelease();
    deadline.removeEventListener('abort', onTimeout);
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
    await callback({ insideFile, outsideFile, insideOriginal, outsideOriginal });
    assert.deepEqual(await readFile(outsideFile), outsideOriginal,
      'An unrelated outside file changed during a controlled fixture test');
  } finally {
    await rm(root, { force: true, recursive: true, maxRetries: 5, retryDelay: 100 });
  }
}
