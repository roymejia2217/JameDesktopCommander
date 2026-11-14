import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const OUTSIDE_BYTES = Buffer.from('OUTSIDE-DIRECTORY-SENTINEL\r\n');
const INSIDE_BYTES = Buffer.from('EXISTING-DIRECTORY-BYTES\r\n');
let sandbox;
let allowed;
let outside;
let prefixSibling;
let home;
let configManager;
let createDirectory;
let originalConfig;

before(async () => {
  sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-create-directory-'));
  allowed = path.join(sandbox, 'allowed');
  outside = path.join(sandbox, 'outside');
  prefixSibling = path.join(sandbox, 'allowed-extra');
  home = path.join(sandbox, 'home');
  for (const dir of [allowed, outside, prefixSibling, home]) {
    await fs.mkdir(dir);
  }
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  assert.equal(path.resolve(os.homedir()), path.resolve(home));
  ({ configManager } = await import('../dist/config-manager.js'));
  ({ createDirectory } = await import('../dist/tools/filesystem.js'));
  originalConfig = await configManager.getConfig();
  await fs.writeFile(path.join(outside, 'sentinel.txt'), OUTSIDE_BYTES);
  await fs.writeFile(path.join(prefixSibling, 'sentinel.txt'), OUTSIDE_BYTES);
});

after(async () => {
  try {
    if (configManager) {
      try {
        if (originalConfig !== undefined) await configManager.updateConfig(originalConfig);
      } finally {
        await configManager.close();
      }
    }
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    if (sandbox) await fs.rm(sandbox, { recursive: true, force: true });
  }
});

async function setAllowedRoots(roots) {
  await configManager.setValue('allowedDirectories', roots);
  assert.deepEqual((await configManager.getConfig()).allowedDirectories, roots);
}

async function assertDirectory(dir) {
  assert.equal((await fs.stat(dir)).isDirectory(), true, dir);
}

async function assertNoDirectory(dir) {
  await assert.rejects(fs.stat(dir), { code: 'ENOENT' });
}

test('creates directory under an existing permitted parent', async () => {
  await setAllowedRoots([allowed]);
  const target = path.join(allowed, 'simple');
  await createDirectory(target);
  await assertDirectory(target);
});

test('creates intermediate parents recursively inside the permitted root', async () => {
  await setAllowedRoots([allowed]);
  const target = path.join(allowed, 'missing', 'one', 'nested');
  await createDirectory(target);
  await assertDirectory(path.join(allowed, 'missing'));
  await assertDirectory(path.join(allowed, 'missing', 'one'));
  await assertDirectory(target);
});

test('repeated directory creation preserves existing file bytes', async () => {
  await setAllowedRoots([allowed]);
  const target = path.join(allowed, 'idempotent');
  await createDirectory(target);
  const file = path.join(target, 'saved.txt');
  await fs.writeFile(file, INSIDE_BYTES);
  await createDirectory(target);
  await assertDirectory(target);
  assert.deepEqual(await fs.readFile(file), INSIDE_BYTES);
});

test('restricted root denies an outside directory and preserves its sentinel', async () => {
  await setAllowedRoots([allowed]);
  const file = path.join(outside, 'sentinel.txt');
  const beforeBytes = await fs.readFile(file);
  const target = path.join(outside, 'denied');
  await assert.rejects(createDirectory(target), /Path not allowed/);
  await assertNoDirectory(target);
  assert.deepEqual(await fs.readFile(file), beforeBytes);
});

test('prefix-collision sibling is denied without side effects', async () => {
  await setAllowedRoots([allowed]);
  const file = path.join(prefixSibling, 'sentinel.txt');
  const beforeBytes = await fs.readFile(file);
  const target = path.join(prefixSibling, 'denied');
  await assert.rejects(createDirectory(target), /Path not allowed/);
  await assertNoDirectory(target);
  assert.deepEqual(await fs.readFile(file), beforeBytes);
});

test('empty allowlist permits creation in a separate owned subtree', async () => {
  await setAllowedRoots([]);
  const target = path.join(outside, 'unrestricted', 'nested');
  await createDirectory(target);
  await assertDirectory(target);
  assert.deepEqual(await fs.readFile(path.join(outside, 'sentinel.txt')), OUTSIDE_BYTES);
});