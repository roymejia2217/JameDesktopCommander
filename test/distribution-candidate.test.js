import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
  await writeFile(join(source, 'dist', 'build-provenance.json'), JSON.stringify({
    schemaVersion: 1, kind: 'git', packageVersion: '0.2.52',
    sourceCommit, workspaceClean: true,
  }) + '\n');
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
    assert.ok(manifest.files.some(item => item.path === 'dist/build-provenance.json'));
    assert.deepEqual(await verifyCandidate(options), manifest);
  });
});

test('portable candidate excludes source-only test fixtures from staged distribution', async () => {
  await withFixture(async options => {
    const sourceFixture = join(options.source, 'test', 'fixtures', 'oc07-synthetic-only.txt');
    await mkdir(dirname(sourceFixture), { recursive: true });
    await writeFile(sourceFixture, 'synthetic-only-receipt-marker\n');
    const manifest = await buildCandidate(options);
    assert.ok(!manifest.files.some(item => item.path.startsWith('test/')));
    assert.deepEqual(await verifyCandidate(options), manifest);
    await assert.rejects(lstat(join(options.destination, 'test')), { code: 'ENOENT' });
  });
});

test('a recomputed SHA-256 manifest cannot authorize extra test or private evidence roots', async () => {
  await withFixture(async options => {
    for (const excluded of [
      'test/fixtures/oc07-synthetic-only.txt',
      '.tmp/security/private-evidence.txt',
      'docs/security/confidential-receipt.txt',
      'runtime/unauthorized-helper.dll',
      'native/unapproved-addon.node',
      'native/jdc-capability-probe.node',
    ]) {
      await buildCandidate(options);
      const payloadPath = join(options.destination, ...excluded.split('/'));
      await mkdir(dirname(payloadPath), { recursive: true });
      const contents = Buffer.from('SYNTHETIC-ONLY-NOT-REAL-TOKEN');
      await writeFile(payloadPath, contents);
      const manifestPath = join(options.destination, 'candidate-manifest.json');
      const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      manifest.files.push({
        path: excluded,
        byteLength: contents.length,
        sha256: createHash('sha256').update(contents).digest('hex'),
      });
      manifest.files.sort((a, b) => a.path.localeCompare(b.path, 'en'));
      manifest.fileCount = manifest.files.length;
      await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
      await assert.rejects(verifyCandidate(options), /unapproved candidate root/i,
        'manifest hash equality must not grant new distribution roots');
    }
  });
});

test('changed payload bytes and added unmanifested files fail closed', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    const targetFile = join(options.destination, 'dist/index.js');
    await writeFile(targetFile, 'export const compromised = true;\n');
    await assert.rejects(verifyCandidate(options), /payload differs/);
    await buildCandidate(options);
    await writeFile(join(options.destination, 'dist', 'untracked-secret.txt'), 'untracked');
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

test('candidate rejects missing, dirty, forged, and ambiguous source identity', async () => {
  await withFixture(async options => {
    const filepath = join(options.source, 'dist/build-provenance.json');
    const clean = { schemaVersion: 1, kind: 'git', packageVersion: '0.2.52',
      sourceCommit, workspaceClean: true };
    for (const malformed of [
      null, { schemaVersion: 1, kind: 'unavailable', packageVersion: '0.2.52' },
      { ...clean, sourceCommit: 'b'.repeat(40) },
      { ...clean, packageVersion: '9.0.0' },
      { ...clean, workspaceClean: false },
      { ...clean, extra: 'unapproved' },
    ]) {
      if (malformed === null) await rm(filepath, { force: true });
      else await writeFile(filepath, JSON.stringify(malformed));
      await assert.rejects(buildCandidate(options),
        /build identity|Git-backed|source commit differs|package version differs|modified source workspace/i);
    }
    await writeFile(filepath, JSON.stringify(clean));
    assert.equal((await buildCandidate(options)).sourceCommit, sourceCommit);
  });
});

test('an altered manifest and matching SHA-256 inventory cannot conceal wrong build commit', async () => {
  await withFixture(async options => {
    await buildCandidate(options);
    const filepath = join(options.destination, 'dist/build-provenance.json');
    const malicious = JSON.stringify({ schemaVersion: 1, kind: 'git', packageVersion: '0.2.52',
      sourceCommit: 'b'.repeat(40), workspaceClean: true }) + '\n';
    await writeFile(filepath, malicious);
    const manifestPath = join(options.destination, 'candidate-manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const record = manifest.files.find(file => file.path === 'dist/build-provenance.json');
    record.byteLength = Buffer.byteLength(malicious);
    record.sha256 = createHash('sha256').update(malicious).digest('hex');
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    await assert.rejects(verifyCandidate(options), /source commit differs/);
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
    await chmod(options.nodeExecutable, 0o755);
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

test('native candidate requires a platform-valid addon and records its exact bytes', async () => {
  await withFixture(async options => {
    const nativeAddon = join(dirname(options.destination), 'native-fixture.node');
    const elf = Buffer.alloc(4096);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]).copy(elf);
    await writeFile(nativeAddon, elf);
    const approved = { ...options, nativeAddon };
    const manifest = await buildCandidate(approved);
    assert.equal(manifest.nativeCapabilityAddon, 'native/jdc-capability-probe.node');
    assert.ok(manifest.files.some(file => file.path === manifest.nativeCapabilityAddon));
    assert.deepEqual(await verifyCandidate(approved), manifest);
    await assert.rejects(verifyCandidate(options), /Native addon must never be silently added/);

    await writeFile(join(options.destination, manifest.nativeCapabilityAddon),
      Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(4092, 1)]));
    await assert.rejects(verifyCandidate(approved), /payload differs/);
  });
});

test('native packaging refuses absent, invalid, symlinked and wrong-platform addons', async () => {
  await withFixture(async options => {
    const nativeAddon = join(dirname(options.destination), 'addon-fixture.node');
    await assert.rejects(buildCandidate({ ...options, nativeAddon }));
    await writeFile(nativeAddon, Buffer.from('not a compiled library'));
    await assert.rejects(buildCandidate({ ...options, nativeAddon }), /incomplete/);
    await writeFile(nativeAddon, Buffer.alloc(4096));
    await assert.rejects(buildCandidate({ ...options, nativeAddon }), /Expected Linux ELF/);
    await rm(nativeAddon);
    await symlink(options.nodeExecutable, nativeAddon);
    await assert.rejects(buildCandidate({ ...options, nativeAddon }),
      /regular file, never a link/);
  });
});
