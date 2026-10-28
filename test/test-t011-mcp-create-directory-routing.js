import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configManager } from '../dist/config-manager.js';
import { createDirectory } from '../dist/tools/filesystem.js';
import { handleCreateDirectory } from '../dist/handlers/filesystem-handlers.js';

async function fixture(mode, callback) {
  const base = await mkdtemp(join(tmpdir(), 'jdc-t011-create-routing-'));
  const allowed = join(base, 'allowed');
  const target = join(allowed, 'child');
  const sentinel = join(base, 'outside.txt');
  const { mkdir } = await import('node:fs/promises');
  await mkdir(allowed);
  await writeFile(sentinel, 'EXTERNAL_UNCHANGED');
  const priorDirs = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () =>
    mode === 'restricted' ? [allowed] : mode === 'unrestricted' ? [] : undefined;
  try {
    await callback({ base, allowed, target, sentinel });
    assert.equal(await readFile(sentinel, 'utf8'), 'EXTERNAL_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = priorDirs;
    await rm(base, { recursive: true, force: true });
  }
}
async function missing(path) {
  await assert.rejects(stat(path), { code: 'ENOENT' });
}

test('restricted MCP mkdir denies without native authority and never performs ambient fs.mkdir', async () => {
  await fixture('restricted', async ({ target }) => {
    await assert.rejects(createDirectory(target), /E_POLICY_UNAVAILABLE/);
    await missing(target);
    const response = await handleCreateDirectory({ path: target });
    assert.equal(response.isError, true);
    assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
    await missing(target);
  });
});

test('legacy-unset policy cannot be treated as explicitly unrestricted', async () => {
  await fixture('legacy-unset', async ({ target }) => {
    await assert.rejects(createDirectory(target), /E_POLICY_UNAVAILABLE/);
    await missing(target);
  });
});
test('explicit unrestricted access retains legacy mkdir semantics without sandbox claim', async () => {
  await fixture('unrestricted', async ({ target }) => {
    await createDirectory(target);
    assert.equal((await stat(target)).isDirectory(), true);
    await createDirectory(target);
  });
});

test('unreadable persisted policy denies before path mutation without fallback', async () => {
  await fixture('restricted', async ({ target }) => {
    configManager.getAllowedDirectoriesForFilesystem = async () => {
      throw Error('simulated watcher or disk policy failure');
    };
    await assert.rejects(createDirectory(target), /E_POLICY_UNAVAILABLE/);
    await missing(target);
  });
});
