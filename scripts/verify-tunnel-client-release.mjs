/** Fail-closed verification of a pinned, official Secure MCP Tunnel archive. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const manifest = JSON.parse(readFileSync(new URL('../packaging/tunnel-client-release.json', import.meta.url), 'utf8'));
const upstreamNames = Object.freeze({
  'win32-x64': 'windows-amd64',
  'linux-x64': 'linux-amd64',
});

export function getPinnedTunnelArtifact(target, lock = manifest) {
  if (!Object.hasOwn(upstreamNames, target)) throw new Error('Unsupported target');
  assert.equal(lock.source, 'openai/tunnel-client', 'Unexpected upstream source');
  assert.match(lock.version, /^\d+\.\d+\.\d+$/, 'Invalid pinned version');
  const item = lock.targets?.[target];
  assert.ok(item, 'Target is not pinned');
  assert.equal(item.archive, `tunnel-client-v${lock.version}-${upstreamNames[target]}.zip`, 'Invalid archive name');
  assert.match(item.sha256, /^[0-9a-f]{64}$/, 'Invalid pinned SHA-256');
  return item;
}

export async function verifyTunnelArchive(target, archivePath, lock = manifest) {
  const item = getPinnedTunnelArtifact(target, lock);
  if (basename(archivePath) !== item.archive) throw new Error('Unexpected archive name');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(archivePath)) hash.update(chunk);
  const actual = hash.digest('hex');
  if (actual !== item.sha256) throw new Error('Official archive SHA-256 mismatch');
  return { target, sha256: actual, archive: item.archive };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    console.error('Usage: node scripts/verify-tunnel-client-release.mjs <target> <archive-path>');
    process.exitCode = 2;
  } else {
    try {
      const result = await verifyTunnelArchive(process.argv[2], process.argv[3]);
      console.log(JSON.stringify(result));
    } catch (error) {
      console.error('Official tunnel archive rejected: ' + (error instanceof Error ? error.message : 'unknown error'));
      process.exitCode = 1;
    }
  }
}
