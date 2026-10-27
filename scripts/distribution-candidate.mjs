#!/usr/bin/env node
/**
 * Internal, unpublished Windows/Linux portable Node distribution candidate.
 * No installer, signing, GitHub Release or service deployment is performed.
 * All byte measurements are made against the staged payload, not the checkout.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { cp, chmod, lstat, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseRuntimeBuildIdentity } from '../dist/tools/runtime-build-identity.js';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const shaPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const targets = new Set(['win32-x64', 'linux-x64']);
const manifestName = 'candidate-manifest.json';
const nativeAddonName = 'native/jdc-capability-probe.node';
// A manifest digest authenticates bytes only relative to its own inventory.
// It must never expand the candidate's explicitly approved payload roots.
const permittedDirectories = new Set(['dist', 'node_modules']);
const permittedRootFiles = new Set([
  'LICENSE', 'NODE-LICENSE', 'package.json', 'package-lock.json', manifestName,
]);

// One required-payload contract for the builder and the independent verifier.
function requiredCandidatePaths(runtimeExecutable) {
  return [
    runtimeExecutable, 'NODE-LICENSE', 'LICENSE', 'package.json',
    'package-lock.json', 'dist/index.js',
    'dist/npm-scripts/verify-ripgrep.js', 'dist/build-provenance.json',
  ];
}

function approvedCandidatePath(path, target, nativeAddonIncluded) {
  const firstSeparator = path.indexOf('/');
  if (firstSeparator === -1) return permittedRootFiles.has(path);
  if (path.startsWith('runtime/')) {
    return path === (target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node');
  }
  if (path.startsWith('native/')) {
    return nativeAddonIncluded && path === nativeAddonName;
  }
  return permittedDirectories.has(path.slice(0, firstSeparator));
}

function safeRelative(value) {
  return typeof value === 'string' && value.length > 0 &&
    !value.includes('\\') && !value.startsWith('/') &&
    value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

function inside(base, candidate) {
  const suffix = relative(base, candidate);
  return suffix !== '' && suffix !== '..' && !suffix.startsWith('..' + sep) &&
    !isAbsolute(suffix);
}

function validTarget(target) {
  assert.ok(targets.has(target), 'Unsupported candidate platform');
}

async function fileRecord(root, filepath) {
  const bytes = await readFile(filepath);
  const path = relative(root, filepath).split(sep).join('/');
  assert.ok(safeRelative(path), 'Unsafe candidate path');
  return { path, byteLength: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}

async function scanRegularFiles(root, target, nativeAddonIncluded) {
  const files = [];
  const seen = new Set();
  async function scan(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (dir === join(root, 'runtime')) {
          assert.fail('Unapproved candidate runtime directory');
        }
        if (dir === root &&
            !(entry.name === 'runtime' || permittedDirectories.has(entry.name) ||
              (nativeAddonIncluded && entry.name === 'native'))) {
          assert.fail('Unapproved candidate root directory');
        }
        await scan(absolute);
      } else {
        // Native library/runtime packages must not contain external or
        // mutable links. In particular no symlink may escape the candidate.
        assert.ok(entry.isFile(), 'Candidate contains link or non-regular entry');
        const record = await fileRecord(root, absolute);
        assert.ok(approvedCandidatePath(record.path, target, nativeAddonIncluded), 'Unapproved candidate root');
        const folded = record.path.toLowerCase();
        assert.ok(!seen.has(folded), 'Case-insensitive candidate path collision');
        seen.add(folded);
        files.push(record);
      }
    }
  }
  await scan(root);
  return files.sort((a, b) => a.path.localeCompare(b.path, 'en'));
}

async function validateNativeAddon(addon, target) {
  assert.ok(isAbsolute(addon), 'Native addon must be an absolute path');
  const metadata = await lstat(addon);
  assert.ok(metadata.isFile(), 'Native addon must be a regular file, never a link');
  const bytes = await readFile(addon);
  assert.ok(bytes.length >= 1024, 'Native addon is incomplete');
  if (target.startsWith('win32')) {
    assert.ok(bytes.subarray(0, 2).equals(Buffer.from('MZ')), 'Expected Windows PE native addon');
  } else {
    assert.ok(bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])),
      'Expected Linux ELF native addon');
  }
}

/** The Git commit in a portable manifest must match its compiled server. */
async function requireCandidateBuildIdentity(directory, version, sourceCommit) {
  let record;
  try {
    const raw = await readFile(join(directory, 'dist/build-provenance.json'), 'utf8');
    record = parseRuntimeBuildIdentity(JSON.parse(raw));
  } catch {
    throw new Error('Candidate build identity is missing or invalid');
  }
  assert.equal(record.kind, 'git', 'Candidate requires Git-backed build identity');
  assert.equal(record.sourceCommit, sourceCommit, 'Candidate source commit differs from build identity');
  assert.equal(record.packageVersion, version, 'Candidate package version differs from build identity');
  assert.equal(record.workspaceClean, true, 'Candidate cannot package a modified source workspace');
}

async function validatedSource(source, sourceCommit) {
  const absolute = await realpath(source);
  for (const name of ['dist/index.js', 'dist/npm-scripts/verify-ripgrep.js', 'package.json', 'package-lock.json', 'LICENSE', 'node_modules']) {
    await lstat(join(absolute, name));
  }
  const pkg = JSON.parse(await readFile(join(absolute, 'package.json'), 'utf8'));
  assert.equal(pkg.private, true, 'Upstream publication namespace must remain private');
  assert.equal(pkg.version.match(/^\d+\.\d+\.\d+$/)?.[0], pkg.version);
  await requireCandidateBuildIdentity(absolute, pkg.version, sourceCommit);
  return { source: absolute, pkg };
}

export async function buildCandidate({ source, destination, nodeExecutable, nodeLicense, target, sourceCommit, runId, attempt, nativeAddon }) {
  validTarget(target);
  assert.match(sourceCommit, shaPattern);
  assert.match(String(runId), /^[0-9]+$/);
  assert.match(String(attempt), /^[1-9][0-9]*$/);
  const checked = await validatedSource(source, sourceCommit);
  assert.ok(isAbsolute(destination) && isAbsolute(nodeExecutable) && isAbsolute(nodeLicense));
  assert.ok(!inside(checked.source, destination) && !inside(destination, checked.source),
    'Candidate destination must not overlap the working source tree');
  assert.notEqual(resolve(destination), checked.source);
  await rm(destination, { recursive: true, force: true });
  await mkdir(join(destination, 'runtime'), { recursive: true });

  for (const name of ['dist', 'node_modules', 'LICENSE', 'package.json', 'package-lock.json']) {
    const sourcePath = join(checked.source, name);
    const destinationPath = join(destination, name);
    const filter = (candidate) => {
      const segment = relative(sourcePath, candidate).split(sep);
      return !segment.includes('.bin');
    };
    await cp(sourcePath, destinationPath, { recursive: true, force: false, errorOnExist: true, filter });
  }
  const binary = target.startsWith('win32') ? 'runtime/node.exe' : 'runtime/node';
  await cp(nodeExecutable, join(destination, binary), { force: false, errorOnExist: true });
  if (target.startsWith('linux')) await chmod(join(destination, binary), 0o755);
  await cp(nodeLicense, join(destination, 'NODE-LICENSE'), { force: false, errorOnExist: true });

  if (nativeAddon !== undefined) {
    await validateNativeAddon(nativeAddon, target);
    await mkdir(join(destination, 'native'), { recursive: true });
    await cp(nativeAddon, join(destination, nativeAddonName),
      { force: false, errorOnExist: true });
  }

  const files = await scanRegularFiles(destination, target, nativeAddon !== undefined);
  assert.ok(files.length > 100, 'Candidate has an unexpectedly small runtime payload');
  for (const mandatory of requiredCandidatePaths(binary)) {
    assert.ok(files.some(file => file.path === mandatory), 'Missing required runtime file');
  }
  const manifest = {
    schemaVersion: 1,
    releaseEligible: false,
    kind: 'unpublished-portable-node-candidate',
    target,
    sourceCommit,
    build: { runId: String(runId), attempt: Number(attempt) },
    nodeVersion: process.version,
    entrypoint: 'dist/index.js',
    runtimeExecutable: binary,
    ...(nativeAddon === undefined ? {} : { nativeCapabilityAddon: nativeAddonName }),
    fileCount: files.length,
    files,
  };
  await writeFile(join(destination, manifestName), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

export async function verifyCandidate({ destination, target, sourceCommit, runId, attempt, nativeAddon }) {
  validTarget(target);
  const manifest = JSON.parse(await readFile(join(destination, manifestName), 'utf8'));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.releaseEligible, false);
  assert.equal(manifest.kind, 'unpublished-portable-node-candidate');
  assert.equal(manifest.target, target);
  assert.equal(manifest.sourceCommit, sourceCommit);
  assert.match(manifest.sourceCommit, shaPattern);
  assert.equal(manifest.build?.runId, String(runId));
  assert.equal(manifest.build?.attempt, Number(attempt));
  assert.equal(manifest.runtimeExecutable, target.startsWith('win32') ? 'runtime/node.exe' : 'runtime/node');
  assert.equal(manifest.entrypoint, 'dist/index.js');
  if (nativeAddon !== undefined) {
    assert.equal(manifest.nativeCapabilityAddon, nativeAddonName,
      'Required capability addon omitted from candidate manifest');
    await validateNativeAddon(join(destination, nativeAddonName), target);
  } else {
    assert.equal(manifest.nativeCapabilityAddon, undefined,
      'Native addon must never be silently added to an unapproved candidate');
  }
  assert.ok(Array.isArray(manifest.files) && manifest.fileCount === manifest.files.length);
  for (const record of manifest.files) {
    assert.ok(safeRelative(record.path) && Number.isSafeInteger(record.byteLength) &&
      record.byteLength >= 0 && digestPattern.test(record.sha256), 'Invalid manifest file entry');
  }
  for (const mandatory of requiredCandidatePaths(manifest.runtimeExecutable)) {
    assert.ok(manifest.files.some(file => file.path === mandatory), 'Missing required runtime file');
  }
  const observed = await scanRegularFiles(destination, target, nativeAddon !== undefined);
  const actual = observed.filter(item => item.path !== manifestName);
  assert.deepEqual(actual, manifest.files, 'Candidate payload differs from the signed-off file inventory');
  const pkg = JSON.parse(await readFile(join(destination, 'package.json'), 'utf8'));
  assert.equal(pkg.private, true);
  await requireCandidateBuildIdentity(destination, pkg.version, sourceCommit);
  const executable = join(destination, manifest.runtimeExecutable);
  const fileInfo = await lstat(executable);
  assert.ok(fileInfo.isFile(), 'Node executable is unavailable');
  return manifest;
}

function runTool(executable, arguments_, cwd) {
  const result = spawnSync(executable, arguments_, {
    cwd, encoding: 'utf8', windowsHide: true, timeout: 20000,
    maxBuffer: 512 * 1024,
    env: { ...process.env, NODE_OPTIONS: '' },
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Packaged Node smoke failed: ' +
    String(result.stderr || result.stdout).slice(0, 1200));
  return String(result.stdout).trim();
}

export async function smokeCandidate(destination, manifest) {
  const executable = join(destination, manifest.runtimeExecutable);
  if (manifest.nativeCapabilityAddon !== undefined) {
    assert.equal(manifest.nativeCapabilityAddon, nativeAddonName);
    // The packaged default addon is intentionally deny-only. Exercise the
    // experimental capability API in its separate CI-only feature build.
    const nativeSmoke = [
      "const addon = require(process.argv[1]);",
      "const keys = Object.keys(addon).sort();",
      "if (keys.length !== 1 || keys[0] !== 'restrictedCapabilityUnavailable') throw Error('Unexpected native addon exports');",
      "if (typeof addon.restrictedCapabilityUnavailable !== 'function') throw Error('Missing native denial entrypoint');",
      "let denied = false;",
      "try { addon.restrictedCapabilityUnavailable(); } catch (e) { denied = /E_CAPABILITY_UNAVAILABLE/.test(String(e)); }",
      "if (!denied) throw Error('Native filesystem capability was not denied');",
    ].join('\n');
    runTool(executable, ['-e', nativeSmoke, join(destination, nativeAddonName)], destination);
  }
  assert.equal(runTool(executable, ['--version'], destination), manifest.nodeVersion);
  runTool(executable, ['--check', join(destination, 'dist/index.js')], destination);
  const script = [
    "import { getRipgrepPath } from './dist/utils/ripgrep-resolver.js';",
    "import { realpathSync } from 'node:fs';",
    "import { resolve, sep } from 'node:path';",
    "import { spawnSync } from 'node:child_process';",
    "const location = realpathSync(await getRipgrepPath());",
    "const relativePath = location.startsWith(resolve('.') + sep);",
    "if (!relativePath) throw new Error('ripgrep resolved outside packaged candidate');",
    "const command = spawnSync(location, ['--version'], {encoding:'utf8',timeout:10000,windowsHide:true});",
    "if (command.error || command.status !== 0 || !command.stdout.includes('ripgrep')) throw new Error('Packaged ripgrep failed');",
  ].join('\n');
  runTool(executable, ['--input-type=module', '--eval', script], destination);
}

async function nodeLicenseFor(executable) {
  const parent = dirname(executable);
  for (const dir of [parent, dirname(parent), dirname(dirname(parent))]) {
    for (const file of ['LICENSE', 'LICENSE.md', 'LICENSE.txt']) {
      const candidate = join(dir, file);
      try {
        const stat = await lstat(candidate);
        if (stat.isFile()) return candidate;
      } catch {
        // The standard Node distribution license may be one level higher.
      }
    }
  }
  throw new Error('Cannot locate Node runtime LICENSE; fail closed');
}


function runNativeTar(args) {
  const result = spawnSync('tar', args, {
    encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 512 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Native tar failed: ' +
    String(result.stderr || result.stdout).slice(0, 1000));
}

async function sha256File(filepath) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(filepath)) hash.update(bytes);
  return hash.digest('hex');
}

// TAR includes dotfiles and preserves executable mode across artifact transport.
export async function createCandidateArchive(destination, archivePath) {
  assert.ok(isAbsolute(destination) && isAbsolute(archivePath));
  assert.ok(!inside(destination, archivePath), 'Archive must be outside candidate');
  const fileInfo = await lstat(destination);
  assert.ok(fileInfo.isDirectory(), 'Candidate stage is missing');
  runNativeTar(['-cf', archivePath, '-C', destination, '.']);
  const archiveInfo = await lstat(archivePath);
  assert.ok(archiveInfo.isFile() && archiveInfo.size > 0, 'Candidate TAR is empty');
}

export async function restoreCandidateArchive(originalArchive, downloadedArchive, destination) {
  assert.ok(isAbsolute(originalArchive) && isAbsolute(downloadedArchive) &&
    isAbsolute(destination));
  assert.notEqual(resolve(originalArchive), resolve(downloadedArchive),
    'Round-trip must validate a separately downloaded artifact');
  assert.equal(await sha256File(downloadedArchive), await sha256File(originalArchive),
    'Downloaded candidate archive differs from uploaded bytes');
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: true });
  runNativeTar(['-xf', downloadedArchive, '-C', destination]);
}

async function main() {
  const action = process.argv[2];
  assert.ok(['build', 'verify', 'smoke', 'archive', 'roundtrip'].includes(action),
    'Expected build, verify, smoke, archive or roundtrip');
  // Fail closed: the unpublished portable candidate is Node-only. The
  // research N-API binary is tested independently but never staged by CLI.
  assert.notEqual(process.env.JDC_CANDIDATE_INCLUDE_NATIVE, '1',
    'Unapproved native capability addon cannot enter portable distribution');
  const target = process.platform + '-' + process.arch;
  validTarget(target);
  assert.equal(process.env.JDC_CANDIDATE_TARGET, target, 'GitHub runner does not match candidate target');
  const temp = process.env.RUNNER_TEMP;
  assert.ok(temp && isAbsolute(temp), 'Runner temp directory required');
  const destination = join(await realpath(temp), 'jdc-candidate-' + target);
  const args = {
    source: projectRoot,
    destination,
    nodeExecutable: process.execPath,
    nodeLicense: await nodeLicenseFor(process.execPath),
    target,
    sourceCommit: process.env.JDC_CANDIDATE_SOURCE_SHA,
    runId: process.env.GITHUB_RUN_ID,
    attempt: process.env.GITHUB_RUN_ATTEMPT,
  };
  const archiveName = 'UNPUBLISHED-jdc-portable-' + target + '.tar';
  const archivePath = join(await realpath(temp), archiveName);
  let manifest;
  if (action === 'build') manifest = await buildCandidate(args);
  else manifest = await verifyCandidate(args);
  if (action === 'smoke') await smokeCandidate(destination, manifest);
  if (action === 'archive') await createCandidateArchive(destination, archivePath);
  if (action === 'roundtrip') {
    const downloadedArchive = join(await realpath(temp), 'jdc-roundtrip-download', archiveName);
    const extracted = join(await realpath(temp), 'jdc-candidate-roundtrip-' + target);
    await restoreCandidateArchive(archivePath, downloadedArchive, extracted);
    manifest = await verifyCandidate({ ...args, destination: extracted });
    await smokeCandidate(extracted, manifest);
  }
  // Never echo file paths, environment values, credentials or file inventories.
  console.log(JSON.stringify({
    result: 'PASS',
    operation: action,
    target: manifest.target,
    files: manifest.fileCount,
    releaseEligible: false,
  }));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error('Distribution candidate gate FAIL: ' + String(error.message).slice(0, 1200));
    process.exitCode = 1;
  });
}
