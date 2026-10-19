import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import lockfile from 'proper-lockfile';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  parseDurableTunnelState,
  TunnelDesiredStateStore,
} from '../dist/platform/windows/tunnel-desired-state-store.js';

const initial = Object.freeze({
  schemaVersion: 1, revision: 1, desired: 'stopped',
  retryAttempts: 0, lastAttemptMs: null,
});
const serialized = (state = initial) => JSON.stringify(state);
const next = { desired: 'running', retryAttempts: 1, lastAttemptMs: 100 };
async function fixture(action) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'jdc-intent-'));
  const file = path.join(dir, 'tunnel-desired-state.json');
  try {
    return await action({ dir, file, store: new TunnelDesiredStateStore(file) });
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('missing desired state fails closed; read never initializes it', () => fixture(async ({ file, store }) => {
  await assert.rejects(store.read(), { code: 'ENOENT' });
  await assert.rejects(store.compareAndSet(1, next), { code: 'ENOENT' });
  await assert.rejects(readFile(file, 'utf8'), { code: 'ENOENT' });
}));

test('strict schema rejects corruption, extensions, invalid intent and retry history', async () => {
  for (const value of [
    '', '{', 'null', '[]', '"running"',
    serialized({ ...initial, schemaVersion: 2 }),
    serialized({ ...initial, desired: 'enabled' }),
    serialized({ ...initial, revision: 0 }),
    serialized({ ...initial, revision: Number.MAX_SAFE_INTEGER }),
    serialized({ ...initial, retryAttempts: -1 }),
    serialized({ ...initial, retryAttempts: 1 }),
    serialized({ ...initial, retryAttempts: 0, lastAttemptMs: 5 }),
    serialized({ ...initial, unforeseen: 'running' }),
    JSON.stringify({ schemaVersion: 1, revision: 1, desired: 'stopped' }),
  ]) {
    assert.throws(() => parseDurableTunnelState(value));
  }
});

test('persistent stopped intent survives reads and is not auto-upgraded', () => fixture(async ({ file, store }) => {
  await writeFile(file, serialized());
  assert.deepEqual(await store.read(), initial);
  assert.equal((await store.read()).desired, 'stopped');
}));

test('CAS accepts valid transition with strictly increasing revision and durable retry history', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, serialized());
    const updated = await store.compareAndSet(1, next);
    assert.deepEqual(updated, { ...initial, revision: 2, ...next });
    assert.deepEqual(await store.read(), updated);
    assert.equal(JSON.parse(await readFile(file, 'utf8')).revision, 2);
    await assert.rejects(store.compareAndSet(1, { ...next, desired: 'stopped' }), /revision conflict/i);
    assert.equal((await store.read()).desired, 'running');
  }));

test('two simultaneous writers cannot both commit the same expected revision', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, serialized());
    const second = new TunnelDesiredStateStore(file);
    const results = await Promise.allSettled([
      store.compareAndSet(1, next),
      second.compareAndSet(1, { desired: 'stopped', retryAttempts: 1, lastAttemptMs: 100 }),
    ]);
    assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
    assert.equal(results.filter((x) => x.status === 'rejected').length, 1);
    assert.equal((await store.read()).revision, 2);
  }));

test('two independent OS processes cannot commit a duplicate revision', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, serialized());
    const worker = fileURLToPath(
      new URL('./fixtures/tunnel-desired-state-worker.js', import.meta.url),
    );
    async function run(desired) {
      const child = fork(worker, [file, desired], {
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      });
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error('Cross-process update deadline exceeded.'));
        }, 10000);
        child.once('message', (message) => {
          clearTimeout(timer);
          resolve(message);
        });
        child.once('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once('exit', (code) => {
          clearTimeout(timer);
          reject(new Error(`Worker exited without result: ${code}`));
        });
      });
    }
    const [a, b] = await Promise.all([run('running'), run('stopped')]);
    const winners = [a, b].filter((x) => x.ok);
    const losers = [a, b].filter((x) => !x.ok);
    assert.equal(winners.length, 1, 'exactly one process must commit');
    assert.equal(losers.length, 1, 'the competing process must fail closed');
    assert.equal(winners[0].revision, 2);
    const loser = losers[0];
    assert.ok(
      /revision conflict/i.test(loser.error) || loser.errorCode === 'ELOCKED',
      `unexpected competing-writer failure: ${loser.errorCode}: ${loser.error}`,
    );
    assert.equal((await store.read()).revision, 2);
  }));

test('an unavailable state lock rejects CAS without changing durable state', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, serialized());
    const release = await lockfile.lock(file, { stale: 30_000, update: 10_000 });
    try {
      await assert.rejects(store.compareAndSet(1, next), { code: 'ELOCKED' });
      assert.deepEqual(await store.read(), initial,
        'lock refusal must not modify the persisted intent or revision');
    } finally {
      await release();
    }
    const updated = await store.compareAndSet(1, next);
    assert.equal(updated.revision, 2, 'CAS succeeds after legitimate lock release');
  }));

test('invalid update never alters the durable state', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, serialized());
    for (const patch of [
      { desired: 'running', retryAttempts: 0, lastAttemptMs: 5 },
      { desired: 'running', retryAttempts: 33, lastAttemptMs: 5 },
      { desired: 'running', retryAttempts: 1, lastAttemptMs: null },
      { ...next, extra: true },
      null,
    ]) {
      await assert.rejects(store.compareAndSet(1, patch));
      assert.deepEqual(await store.read(), initial);
    }
    await assert.rejects(store.compareAndSet(0, next));
  }));

test('failed atomic replacement leaves old durable state untouched', () =>
  fixture(async ({ file }) => {
    await writeFile(file, serialized());
    const store = new TunnelDesiredStateStore(file, {
      replace: async () => { throw new Error('synthetic storage failure'); },
    });
    await assert.rejects(store.compareAndSet(1, next), /synthetic storage failure/);
    assert.deepEqual(await store.read(), initial);
  }));

test('corrupt state fails closed and cannot be overwritten through CAS', () =>
  fixture(async ({ file, store }) => {
    await writeFile(file, '{broken');
    await assert.rejects(store.read(), /corrupt/i);
    await assert.rejects(store.compareAndSet(1, next), /corrupt/i);
    assert.equal(await readFile(file, 'utf8'), '{broken');
  }));

test('symbolic-link state is not trusted', async (t) => {
  await fixture(async ({ dir, file, store }) => {
    const source = path.join(dir, 'source.json');
    await writeFile(source, serialized());
    try {
      await symlink(source, file, 'file');
    } catch (error) {
      if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error?.code)) {
        t.diagnostic('Windows symlink privilege not available; test skipped at fixture level');
        return;
      }
      throw error;
    }
    await assert.rejects(store.read(), /non-linked/i);
    await assert.rejects(store.compareAndSet(1, next), /non-linked/i);
  });
});

test('invalid state path is rejected before filesystem access', () => {
  assert.throws(() => new TunnelDesiredStateStore('relative.json'));
  assert.throws(() => new TunnelDesiredStateStore(path.resolve('arbitrary.json')));
});
