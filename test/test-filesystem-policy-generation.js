import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ConfigManager } from '../dist/config-manager.js';
import {
  POLICY_GENERATION_KEY, POLICY_FINGERPRINT_KEY,
  readCooperativePolicyGeneration, persistedPolicyFingerprint,
} from '../dist/security/filesystem-policy-generation.js';

async function fixture(run) {
  const dir = await mkdtemp(path.join(tmpdir(), 'jdc-policy-epoch-'));
  const configPath = path.join(dir, 'config.json');
  await writeFile(configPath, JSON.stringify({
    welcomeOnboardingEligible: false, allowedDirectories: [],
  }));
  const managers = [];
  const create = async () => {
    const manager = new ConfigManager(configPath);
    await manager.init();
    await manager.close(); // Quiesce fixture watcher, not production behavior.
    managers.push(manager);
    return manager;
  };
  try { await run({ dir, configPath, create }); }
  finally {
    for (const manager of managers) await manager.close();
    await rm(dir, { recursive: true, force: true });
  }
}

test('cooperative writes advance a durable generation through policy ABA', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create(), a = path.join(dir, 'a'), b = path.join(dir, 'b');
    const before = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(before.cooperativeGeneration, null);
    await manager.setValue('allowedDirectories', [a]);
    const one = await manager.getFilesystemPolicyCandidateSnapshot();
    await manager.setValue('allowedDirectories', [b]);
    const two = await manager.getFilesystemPolicyCandidateSnapshot();
    await manager.setValue('allowedDirectories', [a]);
    const three = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.deepEqual([one.cooperativeGeneration, two.cooperativeGeneration,
      three.cooperativeGeneration], [1, 2, 3]);
    assert.equal(one.revision, three.revision,
      'digest equality must not be mistaken for a monotonic revision');
    assert.notEqual(one.revision, two.revision);
  });
});

test('unrelated config writes keep generation and fingerprint stable', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    const first = await manager.getFilesystemPolicyCandidateSnapshot();
    await manager.setValue('telemetryEnabled', false);
    const second = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(first.cooperativeGeneration, second.cooperativeGeneration);
    assert.equal(first.revision, second.revision);
    const persisted = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(persisted[POLICY_GENERATION_KEY], 1);
    assert.equal(persisted[POLICY_FINGERPRINT_KEY], persistedPolicyFingerprint(persisted));
  });
});

test('cross-instance writers serialize policy generation under the existing config lock', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const first = await create(), second = await create();
    await Promise.all([
      first.setValue('allowedDirectories', [path.join(dir, 'a')]),
      second.setValue('allowedDirectories', [path.join(dir, 'b')]),
    ]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(readCooperativePolicyGeneration(disk), 2);
    assert.ok(['a', 'b'].includes(path.basename(disk.allowedDirectories[0])));
  });
});

test('in-place allowlist mutation advances generation rather than mutating the baseline', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    await manager.updateValue('allowedDirectories', (value) => {
      value.push(path.join(dir, 'child'));
      return value;
    });
    const snapshot = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(snapshot.cooperativeGeneration, 2);
    assert.equal(snapshot.allowedRoots.length, 2);
  });
});

test('config reset preserves generation continuity across restricted to unrestricted', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    await manager.resetConfig();
    const after = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(after.mode, 'unrestricted');
    assert.equal(after.cooperativeGeneration, 2);
    assert.deepEqual(after.allowedRoots, []);
  });
});

test('tampering with stamped policy roots fails closed in candidate and further mutations', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    const forged = JSON.parse(await readFile(configPath, 'utf8'));
    forged.allowedDirectories = [path.join(dir, 'outsider')];
    await writeFile(configPath, JSON.stringify(forged));
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.setValue('allowedDirectories', [dir]),
      /Filesystem policy generation unavailable/);
    const unchanged = JSON.parse(await readFile(configPath, 'utf8'));
    assert.deepEqual(unchanged.allowedDirectories, forged.allowedDirectories);
  });
});

test('metadata API cannot manually spoof a generation or its fingerprint', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    await assert.rejects(manager.setValue(POLICY_GENERATION_KEY, 999),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.setValue(POLICY_FINGERPRINT_KEY, '0'.repeat(64)),
      /Filesystem policy generation unavailable/);
    assert.equal((await manager.getFilesystemPolicyCandidateSnapshot()).cooperativeGeneration, 1);
  });
});

test('generation overflow refuses mutation instead of wrapping or resetting to one', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    disk[POLICY_GENERATION_KEY] = Number.MAX_SAFE_INTEGER;
    await writeFile(configPath, JSON.stringify(disk));
    await assert.rejects(manager.setValue('allowedDirectories', [path.join(dir, 'other')]),
      /Filesystem policy generation unavailable/);
    const stored = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(stored[POLICY_GENERATION_KEY], Number.MAX_SAFE_INTEGER);
    assert.deepEqual(stored.allowedDirectories, [dir]);
  });
});

test('a reader refuses truncated cooperative metadata', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    delete disk[POLICY_FINGERPRINT_KEY];
    await writeFile(configPath, JSON.stringify(disk));
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
  });
});
