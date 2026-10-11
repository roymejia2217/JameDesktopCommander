import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configManager, ConfigManager } from '../dist/config-manager.js';
import { validatePath, writeFile as filesystemWriteFile } from '../dist/tools/filesystem.js';

async function withFixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-policy-fail-closed-'));
  try { await run(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

test('failed authorization policy lookup denies filesystem read and write', async () => {
  await withFixture(async root => {
    const target = join(root, 'protected.txt');
    await writeFile(target, 'untouched\n');
    const oldGetConfig = configManager.getConfig;
    const oldGetPolicy = configManager.getAllowedDirectoriesForFilesystem;
    configManager.getConfig = async () => { throw new Error('injected getConfig failure'); };
    configManager.getAllowedDirectoriesForFilesystem = async () => {
      throw new Error('injected policy read failure');
    };
    try {
      await assert.rejects(validatePath(target), /Filesystem access denied/);
      await assert.rejects(filesystemWriteFile(target, 'changed\n', 'rewrite'), /Filesystem access denied/);
      assert.equal(await readFile(target, 'utf8'), 'untouched\n');
    } finally {
      configManager.getConfig = oldGetConfig;
      if (oldGetPolicy === undefined) delete configManager.getAllowedDirectoriesForFilesystem;
      else configManager.getAllowedDirectoriesForFilesystem = oldGetPolicy;
    }
  });
});

test('invalid persisted configuration never degrades into explicit unrestricted policy', async () => {
  await withFixture(async root => {
    const file = join(root, 'config.json');
    await writeFile(file, '{ malformed config');
    const manager = new ConfigManager(file);
    try {
      const ordinaryConfig = await manager.getConfig();
      assert.deepEqual(ordinaryConfig.allowedDirectories, [],
        'existing non-filesystem config fallback is unchanged');
      await assert.rejects(manager.getAllowedDirectoriesForFilesystem(), /authorization policy unavailable/i);
      await writeFile(file, JSON.stringify({ allowedDirectories: [root], welcomeOnboardingEligible: false }));
      assert.deepEqual(await manager.getAllowedDirectoriesForFilesystem(), [root],
        'recovery reads the repaired persisted policy, not the permissive fallback');
    } finally { await manager.close(); }
  });
});

test('explicit empty allowlist stays unrestricted, malformed policy entries are rejected', async () => {
  await withFixture(async root => {
    const file = join(root, 'config.json');
    await writeFile(file, JSON.stringify({ allowedDirectories: [], welcomeOnboardingEligible: false }));
    const manager = new ConfigManager(file);
    try {
      assert.deepEqual(await manager.getAllowedDirectoriesForFilesystem(), []);
      await manager.setValue('allowedDirectories', [root]);
      assert.deepEqual(await manager.getAllowedDirectoriesForFilesystem(), [root]);
      await manager.setValue('allowedDirectories', ['']);
      await assert.rejects(manager.getAllowedDirectoriesForFilesystem(), /Invalid filesystem authorization policy/i);
      await manager.setValue('allowedDirectories', '[]');
      await assert.rejects(manager.getAllowedDirectoriesForFilesystem(), /Invalid filesystem authorization policy/i);
    } finally { await manager.close(); }
  });
});

test('failed config watcher reload invalidates the previously accepted allowlist', async () => {
  await withFixture(async root => {
    const file = join(root, 'config.json');
    await writeFile(file, JSON.stringify({ allowedDirectories: [root], welcomeOnboardingEligible: false }));
    const manager = new ConfigManager(file);
    try {
      assert.deepEqual(await manager.getAllowedDirectoriesForFilesystem(), [root]);
      await writeFile(file, '{ invalid after startup');
      await manager.reloadConfigFromDisk();
      await assert.rejects(manager.getAllowedDirectoriesForFilesystem(), /authorization policy unavailable/i);
    } finally { await manager.close(); }
  });
});
