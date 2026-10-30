import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { validateInstallerInput } from '../scripts/validate-installer-input.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha = 'b'.repeat(40);
const valid = (target = 'win32-x64') => ({
  pkg: { name: '@roymejia2217/jame-desktop-commander', version: '0.2.52', private: true },
  manifest: { schemaVersion: 1, releaseEligible: false,
    kind: 'unpublished-portable-node-candidate', target, sourceCommit: sha,
    entrypoint: 'dist/index.js',
    runtimeExecutable: target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node',
    fileCount: 3, files: [
      { path: 'dist/index.js' }, { path: 'candidate-manifest.json' },
      { path: target === 'win32-x64' ? 'runtime/node.exe' : 'runtime/node' },
    ] },
  target, expectedCommit: sha,
});
test('candidate installer input retains provenance and denies unsafe alterations', () => {
  for (const target of ['win32-x64','linux-x64']) {
    const fixture = valid(target);
    assert.deepEqual(validateInstallerInput(fixture), { version:'0.2.52',target,sourceCommit:sha });
    for (const mutate of [
      x => { x.manifest.releaseEligible = true; },
      x => { x.manifest.sourceCommit = '0'.repeat(40); },
      x => { x.manifest.target = 'linux-arm64'; },
      x => { x.manifest.files[0].path = '../../outside'; },
      x => { x.manifest.files.push({ path:'native/jdc-capability-probe.node' }); },
      x => { x.pkg.private = false; },
    ]) {
      const other = structuredClone(fixture);
      mutate(other);
      assert.throws(() => validateInstallerInput(other));
    }
  }
});
test('Windows installer stays per-user with separate launcher and no service takeover', async () => {
  const iss = await readFile(resolve(root,'packaging/windows/JameDesktopCommander.iss'),'utf8');
  const cmd = await readFile(resolve(root,'packaging/windows/jdc.cmd'),'utf8');
  assert.match(iss, /PrivilegesRequired=lowest/);
  assert.match(iss, /DefaultDirName=\{localappdata\}/);
  assert.match(iss, /Source:.*InputDir/);
  assert.doesNotMatch(iss,/\[(Run|Registry|Services)\]/i);
  assert.match(cmd, /runtime\\node\.exe/);
  assert.match(cmd, /dist\\index\.js/);
});
test('Debian package uses declarative nFPM, not custom dpkg assembly', async () => {
  const config = await readFile(resolve(root,'packaging/linux/nfpm.yaml'),'utf8');
  const launch = await readFile(resolve(root,'packaging/linux/jdc'),'utf8');
  assert.match(config, /name: jame-desktop-commander/);
  assert.match(config, /version: \$\{JDC_INSTALLER_VERSION\}/);
  assert.match(config, /type: tree\s+expand: true/,
    'nFPM requires explicit environment expansion for candidate source paths');
  assert.match(config, /dst: \/opt\/jame-desktop-commander/);
  assert.match(config, /dst: \/usr\/bin\/jdc/);
  assert.doesNotMatch(config, /scripts:|postinstall:|systemctl|curl .*\| *sh/);
  assert.match(launch, /exec \/opt\/jame-desktop-commander\/runtime\/node/);
  assert.match(launch, /"\$@"/);
});
test('existing candidate workflow builds EXE and DEB without publishing release', async () => {
  const workflow = await readFile(resolve(root,'.github/workflows/distribution-candidate.yml'),'utf8');
  assert.match(workflow, /Verify installer provenance/);
  assert.match(workflow, /Compile Inno Setup installer candidate/);
  assert.match(workflow, /Build nFPM Debian installer candidate/);
  assert.match(workflow, /Verify Windows installer install and uninstall/);
  assert.match(workflow, /Verify Debian install and remove/);
  assert.match(workflow, /upload-artifact@/);
  assert.doesNotMatch(workflow, /gh release upload|npm publish/);
});
test('Release Please retains exclusive gated release versioning', async () => {
  const config = await readFile(resolve(root,'release-please-config.json'),'utf8');
  const workflow = await readFile(resolve(root,'.github/workflows/release.yml'),'utf8');
  assert.match(config, /"release-type": "node"/);
  assert.match(workflow, /googleapis\/release-please-action@/);
  for (const issue of [124,139,148]) assert.match(workflow, new RegExp('\\b'+issue+'\\b'));
  assert.match(workflow, /JDC_PRODUCTION_RELEASE_APPROVED/);
});
