import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ConfigManager } from '../dist/config-manager.js';
import { parseFilesystemPolicyCandidate } from '../dist/security/filesystem-policy-snapshot.js';

async function withManager(run, initial = { allowedDirectories: [], welcomeOnboardingEligible: false }) {
  const home = await mkdtemp(path.join(tmpdir(), 'jdc-fs-policy-c3-'));
  const configFile = path.join(home, 'config.json');
  await writeFile(configFile, JSON.stringify(initial));
  const manager = new ConfigManager(configFile);
  try {
    await manager.init();
    // Source-candidate tests control external disk writes without watcher timing.
    // This does not disable watchers in the actual production ConfigManager.
    await manager.close();
    await run({ home, configFile, manager });
  } finally {
    await manager.close();
    await rm(home, { recursive: true, force: true });
  }
}

test('persisted restricted roots are immutable with a stable policy digest', async () => {
  await withManager(async ({ home, manager }) => {
    await manager.setValue('allowedDirectories', [home]);
    const first = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(first.mode, 'restricted');
    assert.deepEqual(first.allowedRoots, [home]);
    assert.ok(Object.isFrozen(first) && Object.isFrozen(first.allowedRoots));
    assert.match(first.revision, /^[0-9a-f]{64}$/);
    assert.throws(() => { first.allowedRoots.push(home); }, TypeError);
    await manager.setValue('telemetryEnabled', false);
    const second = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(first.revision, second.revision);
  });
});

test('direct persisted read observes external root changes without relying on cache', async () => {
  await withManager(async ({ home, configFile, manager }) => {
    await manager.setValue('allowedDirectories', [home]);
    const first = await manager.getFilesystemPolicyCandidateSnapshot();
    const next = path.join(home, 'restricted');
    await writeFile(configFile, JSON.stringify({ allowedDirectories: [next], welcomeOnboardingEligible: false }));
    const second = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.deepEqual(second.allowedRoots, [next]);
    assert.notEqual(first.revision, second.revision);
    assert.deepEqual(first.allowedRoots, [home]);
  });
});

test('explicit empty and root marker remain unrestricted, not a sandbox', async () => {
  await withManager(async ({ home, manager }) => {
    assert.equal((await manager.getFilesystemPolicyCandidateSnapshot()).mode, 'unrestricted');
    await manager.setValue('allowedDirectories', [home, '/']);
    const marker = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(marker.mode, 'unrestricted');
    assert.deepEqual(marker.allowedRoots, []);
  });
});

test('a missing policy key remains distinguishable from explicit unrestricted', async () => {
  await withManager(async ({ manager }) => {
    const snapshot = await manager.getFilesystemPolicyCandidateSnapshot();
    assert.equal(snapshot.mode, 'legacy-unset');
    assert.deepEqual(snapshot.allowedRoots, []);
  }, { welcomeOnboardingEligible: false });
});

test('malformed or noncanonical roots cannot become restricted capabilities', async () => {
  await withManager(async ({ home, configFile, manager }) => {
    const bad = ['[]', [null], [''], ['relative'], [home, home],
      [home + path.sep + '..' + path.sep + 'other']];
    for (const allowedDirectories of bad) {
      await writeFile(configFile, JSON.stringify({ allowedDirectories, welcomeOnboardingEligible: false }));
      assert.deepEqual(JSON.parse(await readFile(configFile, 'utf8')).allowedDirectories, allowedDirectories);
      await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
        /Invalid persisted filesystem policy candidate/);
    }
  });
});

test('POSIX root wildcard remains unrestricted; Windows volume root is not a restricted root', async () => {
  await withManager(async ({ home, configFile, manager }) => {
    const volumeRoot = path.parse(home).root;
    await writeFile(configFile, JSON.stringify({
      allowedDirectories: [volumeRoot], welcomeOnboardingEligible: false,
    }));
    if (volumeRoot === '/') {
      // Existing POSIX '/' sentinel explicitly disables directory restriction.
      const snapshot = await manager.getFilesystemPolicyCandidateSnapshot();
      assert.equal(snapshot.mode, 'unrestricted');
      assert.deepEqual(snapshot.allowedRoots, []);
    } else {
      // A drive/volume root is not the legacy '/' sentinel on Windows.
      await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(),
        /Invalid persisted filesystem policy candidate/);
    }
  });
});

test('corrupted and missing disk config never fall back to stale in-memory policy', async () => {
  await withManager(async ({ home, configFile, manager }) => {
    await manager.setValue('allowedDirectories', [home]);
    await manager.getFilesystemPolicyCandidateSnapshot();
    await writeFile(configFile, '{ malformed');
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(), /Filesystem policy candidate unavailable/);
    await rm(configFile);
    await assert.rejects(manager.getFilesystemPolicyCandidateSnapshot(), /Filesystem policy candidate unavailable/);
  });
});

test('pure parser refuses invalid object shape and classifies legacy policies', () => {
  assert.throws(() => parseFilesystemPolicyCandidate(null));
  assert.throws(() => parseFilesystemPolicyCandidate([]));
  assert.throws(() => parseFilesystemPolicyCandidate({ allowedDirectories: null }));
  assert.equal(parseFilesystemPolicyCandidate({ allowedDirectories: [] }).mode, 'unrestricted');
  assert.equal(parseFilesystemPolicyCandidate({}).mode, 'legacy-unset');
});
