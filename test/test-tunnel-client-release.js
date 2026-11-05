import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyTunnelArchive, getPinnedTunnelArtifact } from '../scripts/verify-tunnel-client-release.mjs';

const fixture = (sha256) => ({ version: '0.0.19', source: 'openai/tunnel-client',
  targets: { 'win32-x64': { archive: 'tunnel-client-v0.0.19-windows-amd64.zip', sha256 } } });

test('official tunnel dependency pins both supported installer targets', () => {
  const win = getPinnedTunnelArtifact('win32-x64');
  const linux = getPinnedTunnelArtifact('linux-x64');
  assert.equal(win.archive, 'tunnel-client-v0.0.19-windows-amd64.zip');
  assert.equal(linux.archive, 'tunnel-client-v0.0.19-linux-amd64.zip');
  for (const item of [win, linux]) assert.match(item.sha256, /^[0-9a-f]{64}$/);
});

test('official tunnel verifier accepts exact file bytes and rejects tampering', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'jdc-tunnel-verify-'));
  try {
    const bytes = Buffer.from('archive test fixture');
    const archive = join(temp, 'tunnel-client-v0.0.19-windows-amd64.zip');
    const sha = createHash('sha256').update(bytes).digest('hex');
    await writeFile(archive, bytes);
    assert.equal((await verifyTunnelArchive('win32-x64', archive, fixture(sha))).sha256, sha);
    await writeFile(archive, Buffer.from('tampered archive'));
    await assert.rejects(verifyTunnelArchive('win32-x64', archive, fixture(sha)), /SHA-256 mismatch/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('official tunnel verifier fails closed on unsupported target or wrong release name', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'jdc-tunnel-verify-'));
  try {
    const archive = join(temp, 'wrong.zip');
    await writeFile(archive, 'payload');
    await assert.rejects(verifyTunnelArchive('win32-x64', archive, fixture('0'.repeat(64))), /archive name/);
    assert.throws(() => getPinnedTunnelArtifact('darwin-arm64'), /Unsupported target/);
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('Windows and Debian installer candidates include the verified official client', async () => {
  const { readFile } = await import('node:fs/promises');
  const root = new URL('../', import.meta.url);
  const windows = await readFile(new URL('packaging/windows/JameDesktopCommander.iss', root), 'utf8');
  const linux = await readFile(new URL('packaging/linux/nfpm.yaml', root), 'utf8');
  const workflow = await readFile(new URL('.github/workflows/distribution-candidate.yml', root), 'utf8');
  assert.match(windows, /JDC_TUNNEL_CLIENT_SOURCE/);
  assert.match(windows, /tools\\tunnel-client/);
  assert.match(linux, /JDC_TUNNEL_CLIENT_SOURCE/);
  assert.match(linux, /tools\/tunnel-client/);
  assert.match(workflow, /verify-tunnel-client-release\.mjs win32-x64/);
  assert.match(workflow, /verify-tunnel-client-release\.mjs linux-x64/);
  assert.match(workflow, /Installed tunnel client/);
  assert.match(workflow, /0\.0\.19/);
});
