import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const INSIDE_BYTES = Buffer.from('ALLOWED-DOMAIN-CONTENT\r\n');
const OUTSIDE_BYTES = Buffer.from('OUTSIDE-DOMAIN-UNCHANGED\r\n');
let sandbox;
let allowed;
let outside;
let prefixSibling;
let home;
let configManager;
let validatePath;
let originalConfig;

before(async () => {
  sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-allowed-directories-'));
  allowed = path.join(sandbox, 'allowed');
  outside = path.join(sandbox, 'outside');
  prefixSibling = path.join(sandbox, 'allowed-extra');
  home = path.join(sandbox, 'home');
  for (const directory of [allowed, outside, prefixSibling, home]) {
    await fs.mkdir(directory);
  }
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  assert.equal(path.resolve(os.homedir()), path.resolve(home));
  // Import after isolating the home path and the node:test config directory.
  ({ configManager } = await import('../dist/config-manager.js'));
  ({ validatePath } = await import('../dist/tools/filesystem.js'));
  originalConfig = await configManager.getConfig();
  await fs.writeFile(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await fs.writeFile(path.join(outside, 'outside.txt'), OUTSIDE_BYTES);
  await fs.writeFile(path.join(prefixSibling, 'prefix.txt'), OUTSIDE_BYTES);
  await fs.writeFile(path.join(home, 'home.txt'), INSIDE_BYTES);
});

after(async () => {
  try {
    if (configManager) {
      try {
        if (originalConfig !== undefined) {
          await configManager.updateConfig(originalConfig);
        }
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

async function allowRoots(roots) {
  await configManager.setValue('allowedDirectories', roots);
  assert.deepEqual((await configManager.getConfig()).allowedDirectories, roots);
}

async function assertReadable(file, expected) {
  const canonical = await validatePath(file);
  assert.deepEqual(await fs.readFile(canonical), expected);
}

async function assertDeniedAndUnchanged(file, expected) {
  const original = await fs.readFile(file);
  assert.deepEqual(original, expected);
  await assert.rejects(validatePath(file), /Path not allowed/);
  assert.deepEqual(await fs.readFile(file), original);
}

test('empty allowlist permits both owned trees', async () => {
  await allowRoots([]);
  await assertReadable(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await assertReadable(path.join(outside, 'outside.txt'), OUTSIDE_BYTES);
  await assertReadable(path.join(home, 'home.txt'), INSIDE_BYTES);
});

test('restricted root grants its children but denies sibling and home', async () => {
  await allowRoots([allowed]);
  await assertReadable(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await assertDeniedAndUnchanged(path.join(outside, 'outside.txt'), OUTSIDE_BYTES);
  await assertDeniedAndUnchanged(path.join(home, 'home.txt'), INSIDE_BYTES);
});

test('a matching directory name prefix is not an authorization', async () => {
  await allowRoots([allowed]);
  await assertReadable(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await assertDeniedAndUnchanged(path.join(prefixSibling, 'prefix.txt'), OUTSIDE_BYTES);
});

test('trailing separator does not widen a restricted root', async () => {
  await allowRoots([allowed + path.sep]);
  await assertReadable(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await assertDeniedAndUnchanged(path.join(outside, 'outside.txt'), OUTSIDE_BYTES);
});

test('home and tilde roots authorize the same home file only', async () => {
  const homeFile = path.join(home, 'home.txt');
  const outsideFile = path.join(outside, 'outside.txt');
  await allowRoots([home]);
  await assertReadable(homeFile, INSIDE_BYTES);
  await assertReadable('~/home.txt', INSIDE_BYTES);
  await assertDeniedAndUnchanged(outsideFile, OUTSIDE_BYTES);
  await allowRoots(['~']);
  await assertReadable(homeFile, INSIDE_BYTES);
  await assertReadable('~/home.txt', INSIDE_BYTES);
  await assertDeniedAndUnchanged(outsideFile, OUTSIDE_BYTES);
});

test('filesystem volume root grants descendants on the same volume', async () => {
  const volumeRoot = path.parse(allowed).root;
  assert.ok(volumeRoot, 'real fixture must reside on a filesystem volume');
  await allowRoots([volumeRoot]);
  await assertReadable(path.join(allowed, 'inside.txt'), INSIDE_BYTES);
  await assertReadable(path.join(outside, 'outside.txt'), OUTSIDE_BYTES);
  await assertReadable(path.join(home, 'home.txt'), INSIDE_BYTES);
});
