import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile as diskWriteFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// This test MUST never run against the installed JDC configuration.
// Run through npm test:unit or use --import=./test/setup-test-environment.js.
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
const {
  readFileFromDisk, readFileInternal, writeFile, readMultipleFiles,
} = await import('../dist/tools/filesystem.js');
const { handleReadFile } = await import('../dist/handlers/filesystem-handlers.js');

async function withPolicy(mode, operation) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-read-write-'));
  const allowed = join(root, 'allowed');
  const localFile = join(allowed, 'private.txt');
  const outside = join(root, 'sentinel.txt');
  await mkdir(allowed);
  await diskWriteFile(localFile, 'INSIDE_SECRET_1403');
  await diskWriteFile(outside, 'OUTSIDE_UNCHANGED');
  const original = configManager.getAllowedDirectoriesForFilesystem;
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'unavailable') throw new Error('persisted policy unavailable');
    if (mode === 'restricted') return [allowed];
    if (mode === 'unset') return undefined;
    return [];
  };
  try {
    await operation({ localFile, outside });
    assert.equal(await readFile(outside, 'utf8'), 'OUTSIDE_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = original;
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unset', 'unavailable']) {
  test(`T011 #139 ${mode} denies pathname reads and writes before side effects`, async () => {
    await withPolicy(mode, async ({ localFile }) => {
      await assert.rejects(readFileFromDisk(localFile), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(readFileInternal(localFile), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(writeFile(localFile, 'CORRUPTED'), /E_POLICY_UNAVAILABLE/);
      const results = await readMultipleFiles([localFile]);
      assert.equal(results.length, 1);
      assert.match(results[0].error, /E_POLICY_UNAVAILABLE/);
      assert.equal(results[0].content, undefined);
      const response = await handleReadFile({ path: localFile });
      assert.equal(response.isError, true);
      assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(JSON.stringify(response), /INSIDE_SECRET_1403/);
      assert.equal(await readFile(localFile, 'utf8'), 'INSIDE_SECRET_1403');
    });
  });
}

test('T011 #139 explicit unrestricted policy preserves byte-accurate read and write', async () => {
  await withPolicy('unrestricted', async ({ localFile }) => {
    assert.equal(
      await readFileInternal(localFile, 0, Number.MAX_SAFE_INTEGER),
      'INSIDE_SECRET_1403',
    );
    const single = await readFileFromDisk(localFile);
    assert.match(single.content, /INSIDE_SECRET_1403/);
    await writeFile(localFile, 'UPDATED', 'rewrite');
    assert.equal(await readFile(localFile, 'utf8'), 'UPDATED');
    const multi = await readMultipleFiles([localFile]);
    assert.match(multi[0].content, /UPDATED/);
  });
});
