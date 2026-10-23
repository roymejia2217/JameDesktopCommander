import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

test('packaged MCP acceptance fails closed when the doctor executable cannot start', async () => {
  const candidate = await mkdtemp(join(tmpdir(), 'jdc-mcp-doctor-entry-'));
  try {
    const runtime = join(candidate, process.platform === 'win32' ? 'invalid-node.exe' : 'invalid-node');
    const entrypoint = join(candidate, 'index.js');
    await writeFile(runtime, 'Not an executable\n');
    await writeFile(entrypoint, 'export {};\n');
    await writeFile(join(candidate, 'candidate-manifest.json'), JSON.stringify({
      releaseEligible: false, target: process.platform + '-' + process.arch,
      runtimeExecutable: basename(runtime), entrypoint: basename(entrypoint),
    }));
    const run = spawnSync(process.execPath, [resolve('scripts/portable-mcp-e2e.mjs'), candidate], {
      encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
    });
    assert.equal(run.error, undefined, 'Acceptance process should launch');
    assert.equal(run.status, 1, 'Invalid packaged runtime must fail closed');
    assert.match(run.stderr, /Packaged portable doctor (did not launch|rejected downloaded candidate)/);
  } finally {
    await rm(candidate, { recursive: true, force: true });
  }
});
