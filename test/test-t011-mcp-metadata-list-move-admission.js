import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Never import configManager before verifying the isolated test home.
const expectedConfig = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR && resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  expectedConfig,
  'E_TEST_ISOLATION_REQUIRED: use the repository test config preloader',
);
const { configManager } = await import('../dist/config-manager.js');
const { getFileInfo, listDirectory, moveFile } = await import('../dist/tools/filesystem.js');
const {
  handleGetFileInfo, handleListDirectory, handleMoveFile, handleRenderWorkspace,
} = await import('../dist/handlers/filesystem-handlers.js');

async function fixture(mode, execute) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-info-list-move-'));
  const allowed = join(root, 'allowed');
  const source = join(allowed, 'internal.txt');
  const destination = join(allowed, 'renamed.txt');
  const outside = join(root, 'external-sentinel.txt');
  await mkdir(allowed);
  await writeFile(source, 'INTERNAL_SENSITIVE_MARKER');
  await writeFile(outside, 'EXTERNAL_UNCHANGED');
  const original = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'unavailable') throw new Error('policy read unavailable');
    if (mode === 'unset') return undefined;
    if (mode === 'restricted') return [allowed];
    return [];
  };
  try {
    await execute({ allowed, source, destination, outside });
    assert.equal(await readFile(outside, 'utf8'), 'EXTERNAL_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = original;
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unset', 'unavailable']) {
  test(`T011 #139 ${mode}: metadata denied before reading object metadata`, async () => {
    await fixture(mode, async ({ source }) => {
      await assert.rejects(getFileInfo(source), /E_POLICY_UNAVAILABLE/);
      const response = await handleGetFileInfo({ path: source });
      assert.equal(response.isError, true);
      assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(JSON.stringify(response), /INTERNAL_SENSITIVE_MARKER/);
    });
  });

  test(`T011 #139 ${mode}: enumeration and directory workspace denied`, async () => {
    await fixture(mode, async ({ allowed }) => {
      await assert.rejects(listDirectory(allowed, 2), /E_POLICY_UNAVAILABLE/);
      for (const [handler, args] of [
        [handleListDirectory, { path: allowed, depth: 2 }],
        [handleRenderWorkspace, { path: allowed, depth: 1 }],
      ]) {
        const response = await handler(args);
        assert.equal(response.isError, true);
        assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
        assert.doesNotMatch(JSON.stringify(response), /internal.txt|external-sentinel.txt/);
      }
    });
  });

  test(`T011 #139 ${mode}: rename denied without source or target mutation`, async () => {
    await fixture(mode, async ({ source, destination }) => {
      await assert.rejects(moveFile(source, destination), /E_POLICY_UNAVAILABLE/);
      const response = await handleMoveFile({ source, destination });
      assert.equal(response.isError, true);
      assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.equal(await readFile(source, 'utf8'), 'INTERNAL_SENSITIVE_MARKER');
      await assert.rejects(stat(destination), { code: 'ENOENT' });
    });
  });
}

test('T011 #139 explicit unrestricted mode retains real metadata, listing and rename', async () => {
  await fixture('unrestricted', async ({ allowed, source, destination }) => {
    const info = await getFileInfo(source);
    assert.equal(info.size, Buffer.byteLength('INTERNAL_SENSITIVE_MARKER'));
    assert.ok((await listDirectory(allowed, 1)).some(x => x.includes('internal.txt')));
    const metadataResponse = await handleGetFileInfo({ path: source });
    assert.notEqual(metadataResponse.isError, true);
    const listingResponse = await handleListDirectory({ path: allowed, depth: 1 });
    assert.notEqual(listingResponse.isError, true);
    const workspace = await handleRenderWorkspace({ path: allowed, depth: 1 });
    assert.notEqual(workspace.isError, true);
    await moveFile(source, destination);
    assert.equal(await readFile(destination, 'utf8'), 'INTERNAL_SENSITIVE_MARKER');
    await assert.rejects(stat(source), { code: 'ENOENT' });
  });
});
