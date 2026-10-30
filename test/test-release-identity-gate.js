import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReleaseIdentity } from '../scripts/verify-release-identity.mjs';

const expectedRepository = 'roymejia2217/JameDesktopCommander';
const version = '0.2.52';
const base = () => ({
  pkg: {
    name: '@roymejia2217/jame-desktop-commander', version, private: false,
    mcpName: 'io.github.roymejia2217/jame-desktop-commander',
    repository: { url: 'https://github.com/roymejia2217/JameDesktopCommander.git' },
  },
  server: {
    name: 'io.github.roymejia2217/jame-desktop-commander',
    repository: { url: 'https://github.com/roymejia2217/JameDesktopCommander' },
    version,
    packages: [{ registryType: 'npm', identifier: '@roymejia2217/jame-desktop-commander', version }],
  },
  manifest: { '.': version },
});
const verify = (data) => verifyReleaseIdentity({ ...data, expectedRepository });

test('accepts consistent owner-controlled npm package identity and release version', () => {
  assert.equal(verify(base()), true);
});
test('rejects current upstream-owned metadata despite green CI', () => {
  const real = {
    pkg: JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')),
    server: JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8')),
    manifest: JSON.parse(readFileSync(new URL('../.release-please-manifest.json', import.meta.url), 'utf8')),
  };
  assert.throws(() => verify(real), /E_RELEASE_IDENTITY_/);
});
test('rejects upstream npm scope and wrong repo even if branding is edited', () => {
  const own = base();
  own.pkg.name = '@wonderwhy-er/desktop-commander';
  assert.throws(() => verify(own), /E_RELEASE_IDENTITY_/);
  const other = base();
  other.pkg.repository.url = 'https://github.com/wonderwhy-er/DesktopCommanderMCP';
  assert.throws(() => verify(other), /E_RELEASE_IDENTITY_/);
});
test('rejects private npm package advertised as a public registry entry', () => {
  const data = base();
  data.pkg.private = true;
  assert.throws(() => verify(data), /E_RELEASE_IDENTITY_/);
});
test('rejects mismatched manifest, MCP name and version', () => {
  for (const mutate of [
    d => { d.manifest['.'] = '0.0.0'; },
    d => { d.server.version = '0.0.0'; },
    d => { d.server.name = 'io.github.wonderwhy-er/desktop-commander'; },
    d => { d.pkg.mcpName = 'io.github.wonderwhy-er/desktop-commander'; },
  ]) {
    const data = base();
    mutate(data);
    assert.throws(() => verify(data), /E_RELEASE_IDENTITY_/);
  }
});
test('rejects registry impersonation and mismatched advertised package version', () => {
  for (const mutate of [
    d => { d.server.packages[0].identifier = '@wonderwhy-er/desktop-commander'; },
    d => { d.server.packages[0].version = '9.9.9'; },
    d => { d.server.repository.url = 'https://github.com/third-party/fork'; },
  ]) {
    const data = base(); mutate(data);
    assert.throws(() => verify(data), /E_RELEASE_IDENTITY_/);
  }
});
test('rejects malformed metadata instead of silently skipping verification', () => {
  const data = base();
  delete data.pkg.repository;
  assert.throws(() => verify(data), /E_RELEASE_IDENTITY_/);
});

test('CLI refuses untrusted repository and accepts genuine owner-owned fixture', () => {
  const dir = mkdtempSync(join(tmpdir(), 'jdc-release-identity-'));
  const script = new URL('../scripts/verify-release-identity.mjs', import.meta.url);
  try {
    const data = base();
    writeFileSync(join(dir, 'package.json'), JSON.stringify(data.pkg));
    writeFileSync(join(dir, 'server.json'), JSON.stringify(data.server));
    writeFileSync(join(dir, '.release-please-manifest.json'), JSON.stringify(data.manifest));
    const invoke = repository => spawnSync(process.execPath, [fileURLToPath(script)], {
      cwd: dir, encoding: 'utf8', timeout: 6000,
      env: { ...process.env, GITHUB_REPOSITORY: repository },
    });
    const denied = invoke('third-party/repo');
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /E_RELEASE_IDENTITY_UNTRUSTED_CI_REPOSITORY/);
    const accepted = invoke(expectedRepository);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /JDC_RELEASE_IDENTITY_ACCEPTED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('release workflow requires identity check before obtaining a write token', () => {
  const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  const command = workflow.indexOf('node scripts/verify-release-identity.mjs');
  const writeToken = workflow.indexOf('name: Create scoped release GitHub App token');
  assert.ok(command > 0 && writeToken > command);
  assert.match(workflow, /if: steps\.readiness\.outputs\.eligible == 'true'/);
});
