import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseRuntimeBuildIdentity, getRuntimeBuildIdentity,
} from '../dist/tools/runtime-build-identity.js';

const SHA = '0123456789abcdef'.repeat(2) + '01234567';

test('accepts commit identity and exposes no filesystem paths', () => {
  const got = parseRuntimeBuildIdentity({
    schemaVersion: 1, kind: 'git', sourceCommit: SHA,
    packageVersion: '0.2.52', workspaceClean: false,
  });
  assert.equal(got.sourceCommit, SHA);
  assert.equal(got.workspaceClean, false);
  assert.equal(Object.keys(got).length, 5);
});

test('malformed revision, unknown keys and unsupported schema fail closed', () => {
  const base = { schemaVersion: 1, kind: 'git', sourceCommit: SHA,
    packageVersion: '0.2.52', workspaceClean: true };
  for (const bad of [
    { ...base, sourceCommit: 'bad' },
    { ...base, workspaceClean: 'true' },
    { ...base, localPath: 'C:\\secrets' },
    { ...base, schemaVersion: 2 },
    { ...base, packageVersion: 'not-semver' },
    { ...base, sourceCommit: null },
  ]) assert.throws(() => parseRuntimeBuildIdentity(bad), /Invalid/);
});

test('absent metadata is unavailable, not a claimed release', async () => {
  const missing = await getRuntimeBuildIdentity(async () => {
    throw new Error('missing build file');
  });
  assert.deepEqual(missing, { schemaVersion: 1, kind: 'unavailable' });
  const malformed = await getRuntimeBuildIdentity(async () => '{"token":"secret"}');
  assert.deepEqual(malformed, { schemaVersion: 1, kind: 'unavailable' });
});

test('packaged metadata is strictly parsed and sanitized', async () => {
  const result = await getRuntimeBuildIdentity(async () =>
    JSON.stringify({ schemaVersion: 1, kind: 'git', sourceCommit: SHA,
      workspaceClean: true, packageVersion: '0.2.52' }));
  assert.equal(result.kind, 'git');
  assert.equal(result.sourceCommit, SHA);
  assert.doesNotMatch(JSON.stringify(result), /token|profile|path/i);
});

test('compiled build embeds package version and does not fabricate a commit', async () => {
  const actual = await getRuntimeBuildIdentity();
  assert.equal(actual.schemaVersion, 1);
  assert.match(actual.packageVersion ?? '', /^\d+\.\d+\.\d+/);
  if (actual.kind === 'git') assert.match(actual.sourceCommit, /^[a-f0-9]{40}$/);
});
