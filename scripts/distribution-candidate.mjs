#!/usr/bin/env node
/**
 * Internal, unpublished Windows/Linux portable Node distribution candidate.
 * No installer, signing, GitHub Release or service deployment is performed.
 * All byte measurements are made against the staged payload, not the checkout.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { cp, chmod, lstat, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const shaPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const targets = new Set(['win32-x64', 'linux-x64']);
const manifestName = 'candidate-manifest.json';

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

async function scanRegularFiles(root) {
  const files = [];
  const seen = new Set();
  async function scan(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = join(dir, entry.name);
      if (entry.isDirectory()) {
        await scan(absolute);
      } else {
        // Native library/runtime packages must not contain external or
        // mutable links. In particular no symlink may escape the candidate.
        assert.ok(entry.isFile(), 'Candidate contains link or non-regular entry');
        const record = await fileRecord(root, absolute);
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

async function validatedSource(source) {
  const absolute = await realpath(source);
  for (const name of ['dist/index.js', 'dist/npm-scripts/verify-ripgrep.js', 'package.json', 'package-lock.json', 'LICENSE', 'node_modules']) {
    await lstat(join(absolute, name));
  }
  const pkg = JSON.parse(await readFile(join(absolute, 'package.json'), 'utf8'));
  assert.equal(pkg.private, true, 'Upstream publication namespace must remain private');
  assert.equal(pkg.version.match(/^\d+\.\d+\.\d+$/)?.[0], pkg.version);
  return { source: absolute, pkg };
}

export async function buildCandidate({ source, destination, nodeExecutable, nodeLicense, target, sourceCommit, runId, attempt }) {
  validTarget(target);
  assert.match(sourceCommit, shaPattern);
  assert.match(String(runId), /^[0-9]+$/);
  assert.match(String(attempt), /^[1-9][0-9]*$/);
  const checked = await validatedSource(source);
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

  const files = await scanRegularFiles(destination);
  assert.ok(files.length > 100, 'Candidate has an unexpectedly small runtime payload');
  for (const mandatory of [binary, 'NODE-LICENSE', 'LICENSE', 'package.json',
    'package-lock.json', 'dist/index.js', 'dist/npm-scripts/verify-ripgrep.js']) {
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
    fileCount: files.length,
    files,
  };
  await writeFile(join(destination, manifestName), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

export async function verifyCandidate({ destination, target, sourceCommit, runId, attempt }) {
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
  assert.ok(Array.isArray(manifest.files) && manifest.fileCount === manifest.files.length);
  for (const record of manifest.files) {
    assert.ok(safeRelative(record.path) && Number.isSafeInteger(record.byteLength) &&
      record.byteLength >= 0 && digestPattern.test(record.sha256), 'Invalid manifest file entry');
  }
  const observed = await scanRegularFiles(destination);
  const actual = observed.filter(item => item.path !== manifestName);
  assert.deepEqual(actual, manifest.files, 'Candidate payload differs from the signed-off file inventory');
  const pkg = JSON.parse(await readFile(join(destination, 'package.json'), 'utf8'));
  assert.equal(pkg.private, true);
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

async function main() {
  const action = process.argv[2];
  assert.ok(['build', 'verify', 'smoke'].includes(action), 'Expected build, verify or smoke');
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
    sourceCommit: process.env.GITHUB_SHA,
    runId: process.env.GITHUB_RUN_ID,
    attempt: process.env.GITHUB_RUN_ATTEMPT,
  };
  let manifest;
  if (action === 'build') manifest = await buildCandidate(args);
  else manifest = await verifyCandidate(args);
  if (action === 'smoke') await smokeCandidate(destination, manifest);
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
