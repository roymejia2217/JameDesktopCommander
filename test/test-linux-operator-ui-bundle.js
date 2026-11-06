import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { parse } from 'yaml';
import {
  createOperatorUiManifest, verifyOperatorUiBundle, LINUX_OPERATOR_UI_FILES,
} from '../scripts/operator-ui-bundle.mjs';

const sha = 'c'.repeat(40);
function syntheticElfAmd64() {
  const bytes = Buffer.alloc(128);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  bytes.writeUInt16LE(0x3e, 18);
  return bytes;
}
async function fixture(callback) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-linux-ui-bundle-'));
  try {
    for (const file of LINUX_OPERATOR_UI_FILES) {
      await mkdir(dirname(join(root, file)), { recursive: true });
      await writeFile(join(root, file), file === 'jdc-tunnel-operator-ui'
        ? syntheticElfAmd64()
        : Buffer.from('reviewed font license fixture: ' + file));
    }
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

test('Linux GUI has exact closed ELF and font-license inventory with source SHA', async () => {
  await fixture(async root => {
    const created = await createOperatorUiManifest({root, expectedCommit: sha, target:'linux-x64'});
    assert.equal(created.target, 'linux-x64');
    assert.equal(created.releaseEligible, false);
    assert.deepEqual(created.files.map(f=>f.path), [...LINUX_OPERATOR_UI_FILES].sort());
    assert.deepEqual(await verifyOperatorUiBundle({root, expectedCommit:sha, target:'linux-x64'}), created);
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit:sha, target:'win32-x64'}), error => {
      assert.equal(error.actual, 'linux-x64');
      assert.equal(error.expected, 'win32-x64');
      return true;
    });
  });
});

test('Linux GUI overlay denies foreign files, modified bytes, and non-ELF executable', async () => {
  await fixture(async root => {
    await createOperatorUiManifest({root, expectedCommit:sha, target:'linux-x64'});
    await appendFile(join(root, 'jdc-tunnel-operator-ui'), 'tamper');
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit:sha, target:'linux-x64'}), /hash|inventory|bytes/i);
  });
  await fixture(async root => {
    await writeFile(join(root, 'jdc-tunnel-operator-ui'), Buffer.from('MZ foreign binary'));
    await assert.rejects(createOperatorUiManifest({root, expectedCommit:sha, target:'linux-x64'}), /ELF|binary|native/i);
  });
  await fixture(async root => {
    await writeFile(join(root, 'unreviewed-helper.so'), 'secret');
    await assert.rejects(createOperatorUiManifest({root, expectedCommit:sha, target:'linux-x64'}), /inventory|unexpected/i);
  });
});

test('Linux GUI manifest and installed bytes cannot claim an approved release', async () => {
  await fixture(async root => {
    await createOperatorUiManifest({root, expectedCommit:sha, target:'linux-x64'});
    const manifestPath = join(root, 'operator-ui-manifest.json');
    const data = JSON.parse(await readFile(manifestPath, 'utf8'));
    data.releaseEligible = true;
    await writeFile(manifestPath, JSON.stringify(data));
    await assert.rejects(verifyOperatorUiBundle({root, expectedCommit:sha, target:'linux-x64'}), /release/i);
  });
});

test('Debian UI packaging uses pinned overlay provenance, desktop launcher and uninstall smoke', async () => {
  const base = new URL('../', import.meta.url);
  const nfpm = await readFile(new URL('packaging/linux/nfpm.yaml', base), 'utf8');
  const wf = await readFile(new URL('.github/workflows/distribution-candidate.yml', base), 'utf8');
  const native = await readFile(new URL('.github/workflows/linux-operator-ui-bundle.yml', base), 'utf8');
  const desktop = await readFile(new URL('packaging/linux/jdc-tunnel-operator.desktop', base), 'utf8');
  const spec = parse(nfpm, { uniqueKeys: true });
  const uiEntries = spec.contents.filter(({src}) =>
    src?.startsWith('${JDC_OPERATOR_UI_SOURCE}/'));
  assert.equal(uiEntries.length, 3, 'Expected binary, manifest and license source');
  for (const item of uiEntries) {
    assert.equal(item.expand, true, `nFPM must expand env in ${item.src}`);
  }
  assert.match(nfpm, /JDC_OPERATOR_UI_SOURCE/);
  assert.match(nfpm, /jdc-tunnel-operator-ui/);
  assert.match(nfpm, /operator-ui-manifest\.json/);
  assert.match(nfpm, /licenses\/operator-ui/);
  assert.match(nfpm, /\/usr\/share\/applications\/jdc-tunnel-operator\.desktop/);
  assert.match(desktop, /Type=Application/);
  assert.match(desktop, /Exec=\/opt\/jame-desktop-commander\/jdc-tunnel-operator-ui/);
  assert.match(desktop, /Terminal=false/);
  assert.match(native, /workflow_call:/);
  assert.match(native, /cargo \+1\.95\.0 build --release --locked/);
  assert.match(native, /epaint_default_fonts-0\.37\.0/);
  assert.match(native, /foldhash-0\.2\.0/);
  assert.match(wf, /linux-operator-ui-bundle\.yml/);
  assert.match(wf, /UNPUBLISHED-jdc-operator-ui-linux-x64/);
  assert.match(wf, /operator-ui-bundle\.mjs verify/);
  assert.match(wf, /--check-installation/);
  assert.match(wf, /dpkg -r jame-desktop-commander/);
  assert.doesNotMatch(wf, /gh release upload|npm publish/);
  assert.doesNotMatch(nfpm, /scripts:|postinstall:|systemctl|curl .*\| *sh/);
});
