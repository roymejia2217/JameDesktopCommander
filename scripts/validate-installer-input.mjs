import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const VALID_TARGETS = new Set(['win32-x64','linux-x64']);
const SHA = /^[0-9a-f]{40}$/;
const FILE = /^[A-Za-z0-9_.@+-]+(?:\/[A-Za-z0-9_.@+-]+)*$/;

export function validateInstallerInput({ pkg, manifest, target, expectedCommit }) {
  assert.ok(VALID_TARGETS.has(target), 'Unexpected installer target');
  assert.match(expectedCommit, SHA, 'Invalid source commit');
  assert.equal(pkg?.private, true, 'Installer must never enable npm registry publishing');
  assert.equal(pkg?.name, '@roymejia2217/jame-desktop-commander');
  assert.match(pkg?.version, /^\d+\.\d+\.\d+$/, 'Invalid installer version');
  assert.equal(manifest?.schemaVersion, 1);
  assert.equal(manifest?.releaseEligible, false, 'Unreviewed installer cannot be release-eligible');
  assert.equal(manifest?.kind, 'unpublished-portable-node-candidate');
  assert.equal(manifest?.target, target);
  assert.equal(manifest?.sourceCommit, expectedCommit);
  assert.equal(manifest?.entrypoint, 'dist/index.js');
  assert.equal(manifest?.runtimeExecutable,
    target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node');
  assert.ok(Array.isArray(manifest?.files) && manifest.files.length > 0);
  assert.equal(manifest?.fileCount, manifest.files.length);
  const seen = new Set();
  for (const entry of manifest.files) {
    assert.ok(FILE.test(entry.path), 'Unsafe or noncanonical candidate entry');
    assert.ok(!entry.path.split('/').includes('..'), 'Traversal entry');
    assert.ok(!entry.path.toLowerCase().startsWith('native/'),
      'Blocked native capability payload must not ship');
    const folded = entry.path.toLowerCase();
    assert.ok(!seen.has(folded), 'Case-folded duplicate');
    seen.add(folded);
  }
  for (const required of ['dist/index.js', manifest.runtimeExecutable]) {
    assert.ok(seen.has(required.toLowerCase()), 'Missing installer runtime path');
  }
  return { version: pkg.version, target, sourceCommit: expectedCommit };
}

async function main() {
  const [source, target, sourceCommit] = process.argv.slice(2);
  assert.ok(source && resolve(source) === source, 'Use absolute candidate directory');
  const [pkg, manifest] = await Promise.all([
    readFile(join(source,'package.json'),'utf8').then(JSON.parse),
    readFile(join(source,'candidate-manifest.json'),'utf8').then(JSON.parse),
  ]);
  const result = validateInstallerInput({
    pkg, manifest, target, expectedCommit: sourceCommit,
  });
  console.log(JSON.stringify({result:'PASS',...result,releaseEligible:false}));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { console.error('Installer candidate denied: ' + e.message); process.exitCode=1; });
}
