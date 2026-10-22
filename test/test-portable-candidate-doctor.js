import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCandidate, verifyCandidate } from '../scripts/distribution-candidate.mjs';
import { inspectPortableCandidate } from '../dist/npm-scripts/portable-doctor.js';

async function fixture(callback) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-portable-doctor-'));
  const source = join(root, 'source');
  const destination = join(root, 'candidate');
  const nodeExecutable = join(root, 'node-fixture');
  const nodeLicense = join(root, 'node-license');
  const sourceCommit = 'a'.repeat(40);
  try {
    await mkdir(join(source, 'dist', 'npm-scripts'), { recursive: true });
    await mkdir(join(source, 'node_modules', 'fixture'), { recursive: true });
    await writeFile(join(source, 'dist/index.js'), 'export {};\n');
    await writeFile(join(source, 'dist/npm-scripts/verify-ripgrep.js'), 'export {};\n');
    await writeFile(join(source, 'dist/build-provenance.json'), JSON.stringify({
      schemaVersion: 1, kind: 'git', packageVersion: '0.2.52',
      sourceCommit, workspaceClean: true,
    }));
    await writeFile(join(source, 'package.json'), JSON.stringify({
      private: true, version: '0.2.52', type: 'module',
    }));
    await writeFile(join(source, 'package-lock.json'), '{}\n');
    await writeFile(join(source, 'LICENSE'), 'test license\n');
    await writeFile(nodeExecutable, 'synthetic node file\n');
    await writeFile(nodeLicense, 'synthetic node license\n');
    for (let i = 0; i < 105; i++) {
      await writeFile(join(source, 'dist', `payload-${i}.txt`), `file-${i}\n`);
    }
    const options = { source, destination, nodeExecutable, nodeLicense,
      target: 'linux-x64', sourceCommit, runId: '123', attempt: '1' };
    await buildCandidate(options);
    await callback({ ...options, root });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('portable doctor verifies a staged candidate without mutating its manifest', async () => {
  await fixture(async ({ destination }) => {
    const manifest = await readFile(join(destination, 'candidate-manifest.json'));
    const result = await inspectPortableCandidate(destination, 'linux-x64');
    assert.deepEqual(result, {
      result: 'PASS', target: 'linux-x64',
      fileCount: JSON.parse(manifest).fileCount, releaseEligible: false,
    });
    assert.deepEqual(await readFile(join(destination, 'candidate-manifest.json')), manifest);
  });
});

test('portable doctor rejects modified or injected bytes and files', async () => {
  await fixture(async ({ destination }) => {
    const payload = join(destination, 'dist/index.js');
    await writeFile(payload, 'export const tampered = true;\n');
    await assert.rejects(inspectPortableCandidate(destination, 'linux-x64'), /integrity/);
    await writeFile(payload, 'export {};\n');
    await writeFile(join(destination, 'dist/untracked.js'), 'leak\n');
    await assert.rejects(inspectPortableCandidate(destination, 'linux-x64'), /Unapproved/);
  });
});

test('portable doctor rejects links and a modified release contract', async () => {
  await fixture(async ({ destination }) => {
    await symlink(join(destination, 'dist'), join(destination, 'link'), 'dir');
    await assert.rejects(inspectPortableCandidate(destination, 'linux-x64'), /Nonregular/);
    await rm(join(destination, 'link'));
    const m = join(destination, 'candidate-manifest.json');
    const original = JSON.parse(await readFile(m, 'utf8'));
    await writeFile(m, JSON.stringify({ ...original, releaseEligible: true }));
    await assert.rejects(inspectPortableCandidate(destination, 'linux-x64'), /contract/);
  });
});

test('portable doctor rejects internally coherent inventories missing required distribution files', async () => {
  await fixture(async ({ destination }) => {
    const manifestPath = join(destination, 'candidate-manifest.json');
    const completeManifest = JSON.parse(await readFile(manifestPath, 'utf8'));

    for (const missing of [
      'LICENSE', 'NODE-LICENSE', 'package-lock.json',
      'dist/npm-scripts/verify-ripgrep.js',
    ]) {
      const originalRecord = completeManifest.files.find(entry => entry.path === missing);
      assert.ok(originalRecord, `Fixture must contain required entry ${missing}`);
      const filePath = join(destination, ...missing.split('/'));
      const bytes = await readFile(filePath);
      const files = completeManifest.files.filter(entry => entry.path !== missing);
      await rm(filePath);
      await writeFile(manifestPath, JSON.stringify({
        ...completeManifest, files, fileCount: files.length,
      }));

      await assert.rejects(
        inspectPortableCandidate(destination, 'linux-x64'),
        /Incomplete portable candidate inventory/,
        `Missing mandatory payload entry must be rejected: ${missing}`,
      );

      await writeFile(filePath, bytes);
      await writeFile(manifestPath, JSON.stringify(completeManifest));
    }
  });
});

test('independent verifier rejects internally coherent inventories missing required files', async () => {
  await fixture(async ({ destination, target, sourceCommit, runId, attempt }) => {
    const options = { destination, target, sourceCommit, runId, attempt };
    const manifestPath = join(destination, 'candidate-manifest.json');
    const completeManifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    assert.equal((await verifyCandidate(options)).fileCount, completeManifest.fileCount);

    for (const missing of [
      'LICENSE', 'NODE-LICENSE', 'package-lock.json',
      'dist/npm-scripts/verify-ripgrep.js',
    ]) {
      assert.ok(completeManifest.files.some(entry => entry.path === missing));
      const filePath = join(destination, ...missing.split('/'));
      const bytes = await readFile(filePath);
      const files = completeManifest.files.filter(entry => entry.path !== missing);
      await rm(filePath);
      await writeFile(manifestPath, JSON.stringify({
        ...completeManifest, files, fileCount: files.length,
      }));

      await assert.rejects(
        verifyCandidate(options),
        /Missing required runtime file/,
        `Independent verifier must reject absent required payload: ${missing}`,
      );

      await writeFile(filePath, bytes);
      await writeFile(manifestPath, JSON.stringify(completeManifest));
    }
  });
});
