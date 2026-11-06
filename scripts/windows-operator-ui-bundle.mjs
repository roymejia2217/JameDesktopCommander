/**
 * Windows installer-only, non-release Rust GUI overlay inventory.
 * SHA-256 verifies staged and installed bytes, not publisher identity.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const name = 'operator-ui-manifest.json';
const digest = /^[a-f0-9]{64}$/;
const sha = /^[a-f0-9]{40}$/;
const font = 'licenses/operator-ui/epaint_default_fonts-0.37.0/';
export const OPERATOR_UI_FILES = Object.freeze([
  'jdc-tunnel-operator-ui.exe',
  font + 'Hack-Regular.txt',
  font + 'OFL.txt',
  font + 'UFL.txt',
  font + 'egui-icons.txt',
  font + 'emoji-icon-font-mit-license.txt',
  'licenses/operator-ui/foldhash-0.2.0/LICENSE',
].sort());

function validatedRoot(root, expectedCommit) {
  assert.ok(typeof root === 'string' && isAbsolute(root),
    'Installer source must be an absolute directory');
  assert.ok(!root.split(/[\\/]/).includes('..'), 'Installer source parent traversal denied');
  assert.match(expectedCommit, sha, 'Invalid source commit');
  return resolve(root);
}
async function regular(root, path, maximum = 180 * 1024 * 1024) {
  const expected = join(root, ...path.split('/'));
  let base = root;
  for (const part of path.split('/')) {
    assert.ok(part && part !== '.' && part !== '..', 'Unsafe bundle name');
    base = join(base, part);
    const info = await lstat(base);
    assert.ok(!info.isSymbolicLink(), 'Operator bundle symlinks are forbidden');
    if (base !== expected) {
      assert.ok(info.isDirectory(), 'Bundle ancestor must be a directory');
    } else {
      assert.ok(info.isFile() && info.size > 0 && info.size <= maximum,
        'Operator bundle file size/type denied');
      return { full: base, size: info.size };
    }
  }
  assert.fail('Empty bundle filename');
}

async function record(root, path) {
  const { full, size } = await regular(root, path,
    path.endsWith('.exe') ? 180 * 1024 * 1024 : 1024 * 1024);
  const bytes = await readFile(full);
  assert.equal(bytes.length, size, 'Operator bundle changed while being read');
  if (path.endsWith('.exe')) {
    assert.ok(bytes[0] === 0x4d && bytes[1] === 0x5a,
      'Native UI binary must have Windows PE header');
  }
  return { path, byteLength: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex') };
}
async function listOverlayFiles(root) {
  const visited = [];
  const walk = async (dir, prefix) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const relative = prefix ? prefix + '/' + entry.name : entry.name;
      assert.ok(!entry.isSymbolicLink(), 'Operator bundle symlinks are forbidden');
      if (entry.isDirectory()) await walk(join(dir, entry.name), relative);
      else {
        assert.ok(entry.isFile(), 'Unexpected special file in GUI overlay');
        visited.push(relative);
      }
    }
  };
  await walk(root, '');
  return visited.sort();
}

function schema(manifest, expectedCommit) {
  assert.deepEqual(Object.keys(manifest).sort(),
    ['fileCount', 'files', 'kind', 'releaseEligible', 'schemaVersion',
      'sourceCommit', 'target'].sort(), 'Operator manifest schema mismatch');
  assert.equal(manifest.kind, 'jdc-native-operator-installer-v1');
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.releaseEligible, false, 'Installer is not approved for release');
  assert.equal(manifest.target, 'win32-x64');
  assert.equal(manifest.sourceCommit, expectedCommit, 'Source commit mismatch');
  assert.equal(manifest.fileCount, OPERATOR_UI_FILES.length);
  assert.deepEqual(manifest.files.map(file => file.path), OPERATOR_UI_FILES,
    'Operator UI manifest missing required files');
  for (const entry of manifest.files) {
    assert.deepEqual(Object.keys(entry).sort(), ['path', 'byteLength', 'sha256'].sort());
    assert.ok(Number.isSafeInteger(entry.byteLength) && entry.byteLength > 0);
    assert.match(entry.sha256, digest);
  }
}
export async function createOperatorUiManifest({root, expectedCommit}) {
  root = validatedRoot(root, expectedCommit);
  assert.deepEqual(await listOverlayFiles(root), OPERATOR_UI_FILES,
    'Unexpected or missing GUI overlay inventory');
  const files = [];
  for (const path of OPERATOR_UI_FILES) files.push(await record(root, path));
  const manifest = {schemaVersion: 1, kind: 'jdc-native-operator-installer-v1',
    releaseEligible: false, target: 'win32-x64', sourceCommit: expectedCommit,
    fileCount: files.length, files};
  await writeFile(join(root, name), JSON.stringify(manifest, null, 2) + '\n', {flag:'wx'});
  return manifest;
}

export async function verifyOperatorUiBundle({
  root, expectedCommit, allowAdditionalFiles = false,
}) {
  root = validatedRoot(root, expectedCommit);
  const path = await regular(root, name, 50 * 1024);
  const manifest = JSON.parse(await readFile(path.full, 'utf8'));
  schema(manifest, expectedCommit);
  if (!allowAdditionalFiles) {
    assert.deepEqual(await listOverlayFiles(root), [...OPERATOR_UI_FILES, name].sort(),
      'Unexpected or missing GUI overlay inventory');
  }
  const records = [];
  for (const file of OPERATOR_UI_FILES) records.push(await record(root, file));
  assert.deepEqual(records, manifest.files, 'Operator overlay bytes/hash inventory mismatch');
  return manifest;
}
async function main() {
  const [action, root, expectedCommit, ...extra] = process.argv.slice(2);
  assert.equal(extra.length, 0, 'Unexpected GUI overlay options');
  assert.ok(['create', 'verify', 'verify-installed'].includes(action),
    'Expected create, verify or verify-installed');
  const options = {root, expectedCommit};
  const result = action === 'create'
    ? await createOperatorUiManifest(options)
    : await verifyOperatorUiBundle({
      ...options, allowAdditionalFiles: action === 'verify-installed',
    });
  console.log(JSON.stringify({result: 'PASS', kind: result.kind, target: result.target,
    sourceCommit: result.sourceCommit, files: result.fileCount,
    releaseEligible: result.releaseEligible}));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error('Native operator installer gate FAIL: ' + String(error.message).slice(0, 200));
    process.exitCode = 1;
  });
}
