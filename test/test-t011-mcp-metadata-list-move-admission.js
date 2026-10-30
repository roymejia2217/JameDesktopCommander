import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Never import the singleton before proving that this process uses the
// repository's isolated test configuration. No installed runtime access.
const expectedConfig = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR &&
    resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  expectedConfig,
  'E_TEST_ISOLATION_REQUIRED: use the repository test config preloader',
);

const { configManager } = await import('../dist/config-manager.js');
const { getFileInfo, listDirectory, moveFile } =
  await import('../dist/tools/filesystem.js');
const {
  handleGetFileInfo, handleListDirectory, handleMoveFile, handleRenderWorkspace,
} = await import('../dist/handlers/filesystem-handlers.js');

async function fixture(mode, run) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-metadata-routing-'));
  const allowed = join(root, 'allowed');
  const inside = join(allowed, 'payload.txt');
  const destination = join(allowed, 'moved.txt');
  const outside = join(root, 'outside.txt');
  await mkdir(allowed);
  await writeFile(inside, 'INSIDE_PRIVATE_148_139');
  await writeFile(outside, 'OUTSIDE_UNCHANGED_148_139');
  const previous = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'failed') throw Error('isolated policy read failed');
    return mode === 'restricted' ? [allowed] : mode === 'unset' ? undefined : [];
  };
  try {
    await run({ allowed, inside, destination, outside });
    assert.equal(await readFile(outside, 'utf8'), 'OUTSIDE_UNCHANGED_148_139');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = previous;
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unset', 'failed']) {
  test(`T011 #139 ${mode} denies metadata, list, move and workspace before I/O`, async () => {
    await fixture(mode, async ({ allowed, inside, destination }) => {
      await assert.rejects(getFileInfo(inside), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(listDirectory(allowed), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(moveFile(inside, destination), /E_POLICY_UNAVAILABLE/);

      const metadata = await handleGetFileInfo({ path: inside });
      const listing = await handleListDirectory({ path: allowed });
      const move = await handleMoveFile({ source: inside, destination });
      const workspace = await handleRenderWorkspace({ path: allowed });
      for (const response of [metadata, listing, move, workspace]) {
        assert.equal(response.isError, true);
        assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
        assert.doesNotMatch(JSON.stringify(response), /INSIDE_PRIVATE_148_139/);
      }

      assert.equal(await readFile(inside, 'utf8'), 'INSIDE_PRIVATE_148_139');
      await assert.rejects(stat(destination), { code: 'ENOENT' });
    });
  });
}

test('T011 #139 explicit unrestricted mode preserves directory and move semantics', async () => {
  await fixture('unrestricted', async ({ allowed, inside, destination }) => {
    const info = await getFileInfo(inside);
    assert.equal(info.isFile, true);
    assert.equal(info.size, Buffer.byteLength('INSIDE_PRIVATE_148_139'));

    const listing = await listDirectory(allowed, 1);
    assert.ok(listing.some(entry => entry.includes('payload.txt')));

    const response = await handleListDirectory({ path: allowed, depth: 1 });
    assert.notEqual(response.isError, true);

    await moveFile(inside, destination);
    await assert.rejects(stat(inside), { code: 'ENOENT' });
    assert.equal(await readFile(destination, 'utf8'), 'INSIDE_PRIVATE_148_139');
  });
});
