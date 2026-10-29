import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configManager, ConfigManager } from '../dist/config-manager.js';
import { validatePath, writeFile as filesystemWriteFile, readFileInternal, createDirectory, moveFile, listDirectory } from '../dist/tools/filesystem.js';

async function withFixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-policy-fail-closed-'));
  try { await run(root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

test('all restricted local filesystem operations deny before path I/O without a native issuer', async () => {
  await withFixture(async root => {
    const source = join(root, 'source.txt');
    const moved = join(root, 'moved.txt');
    const child = join(root, 'child');
    await writeFile(source, 'UNCHANGED');
    const previous = configManager.getAllowedDirectoriesForFilesystem;
    configManager.getAllowedDirectoriesForFilesystem = async () => [root];
    try {
      await assert.rejects(validatePath(source), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(readFileInternal(source), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(filesystemWriteFile(source, 'CHANGED', 'rewrite'), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(createDirectory(child), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(moveFile(source, moved), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(listDirectory(root), /E_POLICY_UNAVAILABLE/);
      assert.equal(await readFile(source, 'utf8'), 'UNCHANGED');
      await assert.rejects(stat(moved), { code: 'ENOENT' });
      await assert.rejects(stat(child), { code: 'ENOENT' });
    } finally {
      configManager.getAllowedDirectoriesForFilesystem = previous;
    }
  });
});

test('legacy-unset and explicit unrestricted modes remain distinguishable', async () => {
  await withFixture(async root => {
    const source = join(root, 'source.txt');
    await writeFile(source, 'BEFORE');
    const previous = configManager.getAllowedDirectoriesForFilesystem;
    try {
      configManager.getAllowedDirectoriesForFilesystem = async () => undefined;
      await assert.rejects(validatePath(source), /E_POLICY_UNAVAILABLE/);
      await assert.rejects(filesystemWriteFile(source, 'AFTER', 'rewrite'), /E_POLICY_UNAVAILABLE/);
      assert.equal(await readFile(source, 'utf8'), 'BEFORE');
      configManager.getAllowedDirectoriesForFilesystem = async () => [];
      await filesystemWriteFile(source, 'AFTER', 'rewrite');
      assert.equal(await readFile(source, 'utf8'), 'AFTER');
    } finally {
      configManager.getAllowedDirectoriesForFilesystem = previous;
    }
  });
});

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
