import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { glob, globSync, hasMagic } from 'glob';

const lock = JSON.parse(readFileSync(
  new URL('../package-lock.json', import.meta.url), 'utf8',
));
const versions = Object.entries(lock.packages)
  .filter(([key]) => /(?:^|\/)node_modules\/minimatch$/.test(key))
  .map(([key, info]) => ({ path: key, version: info.version }));

test('GHSA-g3hv-75wg-m249: no vulnerable minimatch 7.x-10.x remains', () => {
  const affected = versions.filter(({ version }) => {
    const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
    assert.ok(match, 'minimatch lockfile must use fixed semver');
    const major = Number(match[1]);
    return major >= 7 && (major < 11 ||
      (major === 11 && Number(match[2]) === 0 && Number(match[3]) < 1));
  });
  assert.deepEqual(affected, [], 'Dev toolchain must not pin vulnerable minimatch');
});
test('legacy glob consumers retain their compatible minimatch versions', () => {
  // Do not globally force a breaking v11 onto ExcelJS/glob7/archiver.
  const legacy = versions.filter(({ version }) => /^([3456])\./.test(version));
  assert.ok(legacy.length >= 1, 'Legacy consumers must not be overridden globally');
  assert.ok(legacy.some(({ version }) => version.startsWith('3.')));
  assert.ok(legacy.some(({ version }) => version.startsWith('5.')));
});
test('GHSA-3g3m-2fjr-6pw4: no vulnerable glob 9.x-14.0.1 remains', () => {
  const entries = Object.entries(lock.packages)
    .filter(([key]) => /(?:^|\/)node_modules\/glob$/.test(key))
    .map(([key, info]) => ({ path: key, version: info.version }));
  const affected = entries.filter(({ version }) => {
    const [major, minor, patch] = version.split('.').map(Number);
    return major >= 9 && (major < 14 ||
      (major === 14 && (minor === 0 && patch < 2)));
  });
  assert.deepEqual(affected, [], 'Dev glob must use patched >=14.0.2');
  assert.ok(entries.some(({ version }) => /^14\./.test(version)));
  assert.ok(entries.some(({ version }) => /^7\./.test(version)),
    'Do not break legacy ExcelJS and shx glob consumers');
});
test('scoped glob upgrade preserves sync and async Markdown file discovery', async () => {
  assert.equal(hasMagic('test/test*.js'), true);
  const normalize = value => value.replaceAll('\\', '/');
  const sync = globSync('test/test*.js').map(normalize).sort();
  const asyncMatches = (await glob('test/test*.js')).map(normalize).sort();
  assert.deepEqual(sync, asyncMatches, 'Both public glob APIs must return same paths');
  assert.ok(sync.includes('test/test-glob-toolchain-advisories.js'));
});
