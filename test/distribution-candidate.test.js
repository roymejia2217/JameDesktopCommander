import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appendFile, chmod, copyFile, lstat, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  buildCandidate, verifyCandidate, createCandidateArchive, restoreCandidateArchive,
} from '../scripts/distribution-candidate.mjs';

const sourceCommit = 'a'.repeat(40);
const target = 'linux-x64';
const runId = '123456';
const attempt = '1';

async function withFixture(callback) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-distribution-fixture-'));
  const source = join(root, 'source');
  const destination = join(root, 'candidate');
  const binary = join(root, 'fake-node');
  const nodeLicense = join(root, 'node-license');
  await mkdir(join(source, 'dist', 'npm-scripts'), { recursive: true });
  await mkdir(join(source, 'node_modules', 'fixture'), { recursive: true });
  await writeFile(join(source, 'dist', 'index.js'), 'export const example = true;\n');
  await writeFile(join(source, 'dist', 'npm-scripts', 'verify-ripgrep.js'), 'export {};\n');
  await writeFile(join(source, 'package.json'), JSON.stringify({
    name: '@wonderwhy-er/desktop-commander', version: '0.2.52', private: true, type: 'module',
  }));
  await writeFile(join(source, 'package-lock.json'), '{"lockfileVersion":3}\n');
  await writeFile(join(source, 'LICENSE'), 'MIT\n');
  await writeFile(join(source, 'node_modules', 'fixture', 'index.js'), 'export {};\n');
  await writeFile(binary, 'fake test-only executable\n');
  await writeFile(nodeLicense, 'Node license test fixture\n');
  for (let i = 0; i < 105; i++) {
    await writeFile(join(source, 'dist', 'test-file-' + String(i).padStart(3, '0') + '.txt'), 'file:' + i);
  }
  const options = { source, destination, nodeExecutable: binary, nodeLicense,
    target, sourceCommit, runId, attempt };
  try {
    await callback(options);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('candidate contains runtime, license and complete offline SHA-256 file inventory', async () => {
  await withFixture(async options => {
    const manifest = await buildCandidate(options);
    assert.equal(manifest.releaseEligible, false);
    assert.equal(manifest.target, target);
    assert.equal(manifest.sourceCommit, sourceCommit);
    assert.ok(manifest.fileCount > 100);
    assert.ok(manifest.files.some(item => item.path === 'runtime/node'));
    assert.ok(manifest.files.some(item => item.path === 'NODE-LICENSE'));
    assert.deepEqual(await verifyCandidate(options), manifest);
  });
});

test('changed payload bytes and added unmanifested files fail closed', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    const targetFile = join(options.destination, 'dist/index.js');
    await writeFile(targetFile, 'export const compromised = true;\n');
    await assert.rejects(verifyCandidate(options), /payload differs/);
    await buildCandidate(options);
    await writeFile(join(options.destination, 'untracked-secret.txt'), 'untracked');
    await assert.rejects(verifyCandidate(options), /payload differs/);
  });
});

test('platform or source provenance mismatch denies candidate validation', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    await assert.rejects(
      verifyCandidate({ ...options, sourceCommit: 'b'.repeat(40) }),
      /Expected values to be strictly equal/,
    );
    await assert.rejects(
      verifyCandidate({ ...options, target: 'win32-x64' }),
      /Expected values to be strictly equal/,
    );
  });
});

test('symlinks cannot be smuggled into a distribution payload', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    await symlink(join(options.destination, 'dist'),
      join(options.destination, 'redirect-dir'), process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(verifyCandidate(options), /link or non-regular entry/);
  });
});

test('upstream private publication flag cannot silently become publishable', async () => {
  await withFixture(async options => {
    const sourcePkg = join(options.source, 'package.json');
    const pkg = JSON.parse(await readFile(sourcePkg, 'utf8'));
    pkg.private = false;
    await writeFile(sourcePkg, JSON.stringify(pkg));
    await assert.rejects(buildCandidate(options), /private/);
  });
});


test('TAR transport retains hidden dependency files and native Linux executable mode', async () => {
  await withFixture(async options => {
    await writeFile(join(options.source, 'node_modules', 'fixture', '.rels'), 'relationship\n');
    await writeFile(join(options.source, 'node_modules', '.package-lock.json'), '{}\n');
    await chmod(options.binary, 0o755);
    const manifest = await buildCandidate(options);
    const root = dirname(options.destination);
    const original = join(root, 'original.tar');
    const downloaded = join(root, 'downloaded.tar');
    const extracted = join(root, 'roundtrip');
    await createCandidateArchive(options.destination, original);
    await copyFile(original, downloaded);
    await restoreCandidateArchive(original, downloaded, extracted);
    assert.deepEqual(await verifyCandidate({ ...options, destination: extracted }), manifest);
    assert.ok(manifest.files.some(file => file.path === 'node_modules/fixture/.rels'));
    assert.ok(manifest.files.some(file => file.path === 'node_modules/.package-lock.json'));
    if (process.platform === 'linux') {
      assert.ok((await stat(join(extracted, 'runtime/node'))).mode & 0o111,
        'Extracted Linux runtime must remain executable');
    }
  });
});

test('altered downloaded TAR is rejected before extraction', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    const root = dirname(options.destination);
    const original = join(root, 'original.tar');
    const downloaded = join(root, 'tampered.tar');
    const extracted = join(root, 'untrusted-extraction');
    await createCandidateArchive(options.destination, original);
    await copyFile(original, downloaded);
    await appendFile(downloaded, 'tampering\n');
    await assert.rejects(restoreCandidateArchive(original, downloaded, extracted),
      /Downloaded candidate archive differs/);
    await assert.rejects(lstat(extracted), { code: 'ENOENT' });
  });
});
