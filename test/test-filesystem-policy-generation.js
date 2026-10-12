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
    await manager.setFilesystemPolicyCooperatively([a]);
    const one = await manager.getFilesystemPolicyCandidateSnapshot();
    await manager.setFilesystemPolicyCooperatively([b]);
    const two = await manager.getFilesystemPolicyCandidateSnapshot();
    await manager.setFilesystemPolicyCooperatively([a]);
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
    await manager.setFilesystemPolicyCooperatively([dir]);
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
      first.setFilesystemPolicyCooperatively([path.join(dir, 'a')]),
      second.setFilesystemPolicyCooperatively([path.join(dir, 'b')]),
    ]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(readCooperativePolicyGeneration(disk), 2);
    assert.ok(['a', 'b'].includes(path.basename(disk.allowedDirectories[0])));
  });
});

test('opt-in API defensively copies input and legacy in-place edits taint candidate', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    const supplied = [dir];
    await manager.setFilesystemPolicyCooperatively(supplied);
    supplied.push(path.join(dir, 'uncommitted'));
    assert.deepEqual((await manager.getFilesystemPolicyCandidateSnapshot()).allowedRoots, [dir]);
    await manager.updateValue('allowedDirectories', (value) => {
      value.push(path.join(dir, 'child'));
      return value;
    });
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
    // Production's pre-existing generic update still succeeds; it does not
    // silently become a cooperative, trusted policy transaction.
    assert.deepEqual(await manager.getValue('allowedDirectories'),
      [dir, path.join(dir, 'child')]);
  });
});

test('opt-in reset advances generation; ordinary reset preserves legacy semantics', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setFilesystemPolicyCooperatively([dir]);
    await manager.setFilesystemPolicyCooperatively([]);
    const after = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(after.mode, 'unrestricted');
    assert.equal(after.cooperativeGeneration, 2);
    await manager.resetConfig();
    const legacy = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(legacy.mode, 'unrestricted');
    assert.equal(legacy.cooperativeGeneration, null);
  });
});

test('tampered stamped roots deny opt-in mutation but never break unrelated legacy writes', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setFilesystemPolicyCooperatively([dir]);
    const forged = JSON.parse(await readFile(configPath, 'utf8'));
    forged.allowedDirectories = [path.join(dir, 'outsider')];
    await writeFile(configPath, JSON.stringify(forged));
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.setFilesystemPolicyCooperatively([dir]),
      /Filesystem policy generation unavailable/);
    await manager.setValue('telemetryEnabled', false);
    await manager.updateValue('telemetryEnabled', () => true);
    await manager.updateConfig({ telemetryEnabled: false });
    const unchanged = JSON.parse(await readFile(configPath, 'utf8'));
    assert.deepEqual(unchanged.allowedDirectories, forged.allowedDirectories);
    assert.equal(unchanged.telemetryEnabled, false);
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
  });
});

test('metadata API cannot manually spoof a generation or its fingerprint', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setFilesystemPolicyCooperatively([dir]);
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
    await manager.setFilesystemPolicyCooperatively([dir]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    disk[POLICY_GENERATION_KEY] = Number.MAX_SAFE_INTEGER;
    await writeFile(configPath, JSON.stringify(disk));
    await assert.rejects(manager.setFilesystemPolicyCooperatively([path.join(dir, 'other')]),
      /Filesystem policy generation unavailable/);
    const stored = JSON.parse(await readFile(configPath, 'utf8'));
    assert.equal(stored[POLICY_GENERATION_KEY], Number.MAX_SAFE_INTEGER);
    assert.deepEqual(stored.allowedDirectories, [dir]);
  });
});

test('a reader refuses truncated cooperative metadata', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setFilesystemPolicyCooperatively([dir]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    delete disk[POLICY_FINGERPRINT_KEY];
    await writeFile(configPath, JSON.stringify(disk));
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
  });
});
test('ordinary legacy policy writes never stamp or block restored configuration', async () => {
  await fixture(async ({ dir, configPath, create }) => {
    const manager = await create();
    await manager.setValue('allowedDirectories', [dir]);
    await manager.updateValue('allowedDirectories', () => [path.join(dir, 'next')]);
    const old = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(old.cooperativeGeneration, null);
    await manager.setFilesystemPolicyCooperatively([dir]);
    const disk = JSON.parse(await readFile(configPath, 'utf8'));
    disk.allowedDirectories = [path.join(dir, 'legacy-restore')];
    await writeFile(configPath, JSON.stringify(disk));
    await manager.setValue('allowedDirectories', [dir]);
    await manager.setValue('telemetryEnabled', true);
    const restored = JSON.parse(await readFile(configPath, 'utf8'));
    assert.deepEqual(restored.allowedDirectories, [dir]);
    // The stale stamp is not repaired implicitly, so the candidate stays denied.
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
      /Filesystem policy generation unavailable/);
  });
});

test('reserved policy markers cannot be forged by any ordinary config setter', async () => {
  await fixture(async ({ dir, create }) => {
    const manager = await create();
    await manager.setFilesystemPolicyCooperatively([dir]);
    await assert.rejects(manager.updateValue(POLICY_GENERATION_KEY, () => 1000),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.setValueNonBlocking(POLICY_FINGERPRINT_KEY, 'x'),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.updateValueNonBlocking(POLICY_GENERATION_KEY, () => 1000),
      /Filesystem policy generation unavailable/);
    await assert.rejects(manager.updateConfig({ [POLICY_GENERATION_KEY]: 1000 }),
      /Filesystem policy generation unavailable/);
    assert.equal((await manager.getFilesystemPolicyCandidateSnapshot()).cooperativeGeneration, 1);
  });
});

