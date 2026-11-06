import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import {
  createOperatorUiManifest, verifyOperatorUiBundle, OPERATOR_UI_FILES,
} from '../scripts/operator-ui-bundle.mjs';

const sha = 'a'.repeat(40);
async function fixture(callback) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-operator-bundle-'));
  try {
    for (const file of OPERATOR_UI_FILES) {
      await mkdir(dirname(join(root, file)), { recursive: true });
      await writeFile(join(root, file), file.endsWith('.exe')
        ? Buffer.from('MZ synthetic-not-executable fixture')
        : Buffer.from('reviewed text fixture: ' + file));
    }
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
test('installer GUI overlay has an exact closed inventory and SHA-256 provenance', async () => {
  await fixture(async root => {
    const manifest = await createOperatorUiManifest({ root, expectedCommit: sha });
    assert.equal(manifest.releaseEligible, false);
    assert.equal(manifest.sourceCommit, sha);
    assert.equal(manifest.target, 'win32-x64');
    assert.deepEqual(manifest.files.map(f => f.path), [...OPERATOR_UI_FILES].sort());
    assert.deepEqual(await verifyOperatorUiBundle({root, expectedCommit: sha}), manifest);
    assert.equal((await readFile(join(root,'operator-ui-manifest.json'),'utf8')).includes('MZ'), false);
  });
});

test('edited, missing or injected operator payloads fail closed', async () => {
  await fixture(async root => {
    await createOperatorUiManifest({root, expectedCommit: sha});
    await appendFile(join(root, 'jdc-tunnel-operator-ui.exe'), 'tamper');
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit: sha}), /inventory|hash|bytes/i);
  });
  await fixture(async root => {
    await rm(join(root, OPERATOR_UI_FILES[1]));
    await assert.rejects(createOperatorUiManifest({root, expectedCommit: sha}), /missing|required|inventory/i);
  });
  await fixture(async root => {
    await writeFile(join(root, 'helper.dll'), 'injected');
    await assert.rejects(createOperatorUiManifest({root, expectedCommit: sha}), /unexpected|unapproved|inventory/i);
  });
});
test('commit mismatch, missing manifest and mutable release marker are denied', async () => {
  await fixture(async root => {
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit: sha}), /manifest/i);
    await createOperatorUiManifest({root, expectedCommit: sha});
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit: 'b'.repeat(40)}), /commit/i);
    const p = join(root, 'operator-ui-manifest.json');
    const manifest = JSON.parse(await readFile(p, 'utf8'));
    manifest.releaseEligible = true;
    await writeFile(p, JSON.stringify(manifest));
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit: sha}), /release|candidate/i);
  });
});

test('post-install validation accepts other packaged Node files but verifies GUI bytes', async () => {
  await fixture(async root => {
    await createOperatorUiManifest({root, expectedCommit: sha});
    await mkdir(join(root, 'runtime'));
    await writeFile(join(root, 'runtime', 'node.exe'), 'unrelated installed runtime fixture');
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit: sha}), /unexpected|inventory/i);
    const manifest = await verifyOperatorUiBundle({
      root, expectedCommit: sha, allowAdditionalFiles: true,
    });
    assert.equal(manifest.files.length, OPERATOR_UI_FILES.length);
    await appendFile(join(root,'licenses','operator-ui','epaint_default_fonts-0.37.0','UFL.txt'), 'tamper');
    await assert.rejects(verifyOperatorUiBundle({
      root, expectedCommit: sha, allowAdditionalFiles: true,
    }), /inventory|hash|bytes/i);
  });
});

test('Windows installer uses only the reviewed UI overlay and an explicit GUI shortcut', async () => {
  const iss = await readFile(new URL('../packaging/windows/JameDesktopCommander.iss', import.meta.url), 'utf8');
  assert.match(iss, /GetEnv\("JDC_OPERATOR_UI_SOURCE"\)/);
  assert.match(iss, /#error JDC_OPERATOR_UI_SOURCE/);
  assert.match(iss, /Source: "\{#OperatorUiDir\}\\jdc-tunnel-operator-ui\.exe"/);
  assert.match(iss, /Source: "\{#OperatorUiDir\}\\operator-ui-manifest\.json"/);
  assert.match(iss, /Source: "\{#OperatorUiDir\}\\licenses\\\*"/);
  assert.match(iss, /Name: "\{userprograms\}\\JameDesktopCommander - Tunnel Operator"/);
  assert.match(iss, /PrivilegesRequired=lowest/);
  assert.doesNotMatch(iss, /\[(Run|Registry|Services)\]/);
});

test('Windows candidate builds exact locked UI source, checks notices and cleans installed copy', async () => {
  const wf = await readFile(new URL('../.github/workflows/distribution-candidate.yml', import.meta.url), 'utf8');
  const native = await readFile(new URL('../.github/workflows/windows-operator-ui-bundle.yml', import.meta.url), 'utf8');
  assert.match(native, /Build pinned Windows operator UI/);
  assert.match(native, /cargo \+1\.95\.0 build --release --locked/);
  assert.match(native, /epaint_default_fonts-0\.37\.0/);
  assert.match(native, /foldhash-0\.2\.0/);
  assert.match(native, /operator-ui-bundle\.mjs create/);
  assert.match(native, /operator-ui-bundle\.mjs verify/);
  assert.match(native, /JDC_OPERATOR_UI_SOURCE:/);
  assert.match(wf, /operator-ui-bundle\.mjs verify-installed/);
  assert.match(wf, /JDC_OPERATOR_UI_SOURCE:/);
  assert.match(wf, /jdc-tunnel-operator-ui\.exe/);
  assert.match(wf, /operator-ui-manifest\.json/);
  assert.match(wf, /Test-Path/);
  assert.doesNotMatch(wf, /gh release upload|npm publish/);
});

test('Windows runner accepts equivalent absolute paths with forward slashes', {
  skip: process.platform !== 'win32',
}, async () => {
  await fixture(async root => {
    const portable = root.replaceAll('\\', '/');
    await createOperatorUiManifest({root: portable, expectedCommit: sha});
    assert.equal((await verifyOperatorUiBundle({
      root: portable, expectedCommit: sha,
    })).sourceCommit, sha);
  });
});

test('native GUI build is isolated from the restricted portable Node packaging job', async () => {
  const candidate = await readFile(new URL('../.github/workflows/distribution-candidate.yml', import.meta.url), 'utf8');
  const nativeWorkflow = await readFile(new URL('../.github/workflows/windows-operator-ui-bundle.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(candidate, /\b(?:cargo|rustup)\b/,
    'Portable Node candidate must never compile any Rust native authority');
  assert.match(candidate, /uses: \.\/\.github\/workflows\/windows-operator-ui-bundle\.yml/);
  assert.match(candidate, /needs: \[windows-operator-ui, linux-operator-ui\]/);
  assert.match(candidate, /name: UNPUBLISHED-jdc-operator-ui-win32-x64/);
  assert.match(nativeWorkflow, /workflow_call:/);
  assert.match(nativeWorkflow, /Build pinned Windows operator UI/);
  assert.match(nativeWorkflow, /cargo \+1\.95\.0 build --release --locked/);
  assert.doesNotMatch(nativeWorkflow, /capability-probe|napi|research_impl|receiver-test-fixture/);
});
