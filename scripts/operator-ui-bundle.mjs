/**
 * Cross-platform, non-release Rust GUI overlay inventory.
 * Each OS has a fixed, distinct allowlist; SHA-256 checks staged and installed
 * bytes against the exact source SHA but does not prove publisher identity.
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
const licenseFiles = Object.freeze([
  font + 'Hack-Regular.txt',
  font + 'OFL.txt',
  font + 'UFL.txt',
  font + 'egui-icons.txt',
  font + 'emoji-icon-font-mit-license.txt',
  'licenses/operator-ui/foldhash-0.2.0/LICENSE',
]);
export const OPERATOR_UI_FILES = Object.freeze(['jdc-tunnel-operator-ui.exe', ...licenseFiles].sort());
export const LINUX_OPERATOR_UI_FILES = Object.freeze(['jdc-tunnel-operator-ui', ...licenseFiles].sort());
function targetFiles(target) {
  if (target === 'win32-x64') return OPERATOR_UI_FILES;
  if (target === 'linux-x64') return LINUX_OPERATOR_UI_FILES;
  assert.fail('Unsupported native operator target');
}

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
  const executable = path === 'jdc-tunnel-operator-ui.exe' ||
    path === 'jdc-tunnel-operator-ui';
  const { full, size } = await regular(root, path,
    executable ? 180 * 1024 * 1024 : 1024 * 1024);
  const bytes = await readFile(full);
  assert.equal(bytes.length, size, 'Operator bundle changed while being read');
  if (path.endsWith('.exe')) {
    assert.ok(bytes[0] === 0x4d && bytes[1] === 0x5a,
      'Native UI binary must have Windows PE header');
  }
  if (path === 'jdc-tunnel-operator-ui') {
    assert.ok(bytes.length >= 64 &&
      bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c &&
      bytes[3] === 0x46 && bytes[4] === 2 && bytes[5] === 1 &&
      bytes.readUInt16LE(18) === 0x3e,
      'Linux operator requires an ELF64 little-endian AMD64 binary');
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

function schema(manifest, expectedCommit, target) {
  const files = targetFiles(target);
  assert.deepEqual(Object.keys(manifest).sort(),
    ['fileCount', 'files', 'kind', 'releaseEligible', 'schemaVersion',
      'sourceCommit', 'target'].sort(), 'Operator manifest schema mismatch');
  assert.equal(manifest.kind, 'jdc-native-operator-installer-v1');
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.releaseEligible, false, 'Installer is not approved for release');
  assert.equal(manifest.target, target);
  assert.equal(manifest.sourceCommit, expectedCommit, 'Source commit mismatch');
  assert.equal(manifest.fileCount, files.length);
  assert.deepEqual(manifest.files.map(file => file.path), files,
    'Operator UI manifest missing required files');
  for (const entry of manifest.files) {
    assert.deepEqual(Object.keys(entry).sort(), ['path', 'byteLength', 'sha256'].sort());
    assert.ok(Number.isSafeInteger(entry.byteLength) && entry.byteLength > 0);
    assert.match(entry.sha256, digest);
  }
}
export async function createOperatorUiManifest({root, expectedCommit, target = 'win32-x64'}) {
  root = validatedRoot(root, expectedCommit);
  const names = targetFiles(target);
  assert.deepEqual(await listOverlayFiles(root), names,
    'Unexpected or missing GUI overlay inventory');
  const files = [];
  for (const path of names) files.push(await record(root, path));
  const manifest = {schemaVersion: 1, kind: 'jdc-native-operator-installer-v1',
    releaseEligible: false, target, sourceCommit: expectedCommit,
    fileCount: files.length, files};
  await writeFile(join(root, name), JSON.stringify(manifest, null, 2) + '\n', {flag:'wx'});
  return manifest;
}

export async function verifyOperatorUiBundle({
  root, expectedCommit, target = 'win32-x64', allowAdditionalFiles = false,
}) {
  root = validatedRoot(root, expectedCommit);
  const names = targetFiles(target);
  const path = await regular(root, name, 50 * 1024);
  const manifest = JSON.parse(await readFile(path.full, 'utf8'));
  schema(manifest, expectedCommit, target);
  if (!allowAdditionalFiles) {
    assert.deepEqual(await listOverlayFiles(root), [...names, name].sort(),
      'Unexpected or missing GUI overlay inventory');
  }
  const records = [];
  for (const file of names) records.push(await record(root, file));
  assert.deepEqual(records, manifest.files, 'Operator overlay bytes/hash inventory mismatch');
  return manifest;
}
async function main() {
  const [action, root, expectedCommit, target = 'win32-x64', ...extra] = process.argv.slice(2);
  assert.equal(extra.length, 0, 'Unexpected GUI overlay options');
  assert.ok(['create', 'verify', 'verify-installed'].includes(action),
    'Expected create, verify or verify-installed');
  const options = {root, expectedCommit, target};
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
