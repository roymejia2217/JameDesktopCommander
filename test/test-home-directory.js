import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const HOME_BYTES = Buffer.from('HOME-DOCUMENT-CONTROL\r\n');
const OUTSIDE_BYTES = Buffer.from('OUTSIDE-HOME-UNCHANGED\r\n');
let sandbox;
let home;
let docs;
let outside;
let configManager;
let validatePath;
let createDirectory;
let writeFile;
let readFile;
let listDirectory;
let originalConfig;

before(async () => {
  sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-home-directory-'));
  home = path.join(sandbox, 'home');
  docs = path.join(home, 'Documents');
  outside = path.join(sandbox, 'outside');
  await fs.mkdir(docs, { recursive: true });
  await fs.mkdir(outside);
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  assert.equal(path.resolve(os.homedir()), path.resolve(home));
  ({ configManager } = await import('../dist/config-manager.js'));
  ({ validatePath, createDirectory, writeFile, readFile, listDirectory } =
    await import('../dist/tools/filesystem.js'));
  originalConfig = await configManager.getConfig();
  await fs.writeFile(path.join(docs, 'note.txt'), HOME_BYTES);
  await fs.writeFile(path.join(outside, 'sentinel.txt'), OUTSIDE_BYTES);
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

async function setAllowedRoots(roots) {
  await configManager.setValue('allowedDirectories', roots);
  assert.deepEqual((await configManager.getConfig()).allowedDirectories, roots);
}

test('tilde resolves exactly to the isolated home root', async () => {
  await setAllowedRoots([home]);
  assert.equal(await validatePath('~'), await fs.realpath(home));
});

test('tilde documents path resolves inside the isolated home', async () => {
  await setAllowedRoots([home]);
  assert.equal(await validatePath('~/Documents'), await fs.realpath(docs));
  assert.equal(await validatePath('~/Documents/note.txt'),
    await fs.realpath(path.join(docs, 'note.txt')));
});

test('tilde configured root permits home files and denies outside bytes', async () => {
  await setAllowedRoots(['~']);
  const canonical = await validatePath(path.join(docs, 'note.txt'));
  assert.deepEqual(await fs.readFile(canonical), HOME_BYTES);
  const sentinel = path.join(outside, 'sentinel.txt');
  await assert.rejects(validatePath(sentinel), /Path not allowed/);
  assert.deepEqual(await fs.readFile(sentinel), OUTSIDE_BYTES);
});

test('absolute home configured root grants tilde access and denies siblings', async () => {
  await setAllowedRoots([home]);
  assert.equal(await validatePath('~/Documents/note.txt'),
    await fs.realpath(path.join(docs, 'note.txt')));
  const sentinel = path.join(outside, 'sentinel.txt');
  await assert.rejects(validatePath(sentinel), /Path not allowed/);
  assert.deepEqual(await fs.readFile(sentinel), OUTSIDE_BYTES);
});

test('tilde file operations create write read and list inside home', async () => {
  await setAllowedRoots([home]);
  const tildeDir = '~/.jdc-owned-fixture';
  const tildeFile = '~/.jdc-owned-fixture/data.txt';
  const expected = 'HOME-FILE-OPERATIONS';
  await createDirectory(tildeDir);
  assert.equal((await fs.stat(path.join(home, '.jdc-owned-fixture'))).isDirectory(), true);
  await writeFile(tildeFile, expected);
  assert.equal(await fs.readFile(path.join(home, '.jdc-owned-fixture', 'data.txt'), 'utf8'),
    expected);
  const result = await readFile(tildeFile);
  assert.equal(typeof result.content, 'string');
  assert.ok(result.content.includes(expected), 'read_file must expose written bytes');
  const entries = await listDirectory(tildeDir);
  assert.ok(entries.includes('[FILE] data.txt'), 'list_directory must expose the new file');
});

test('outside-home write is denied without modifying existing bytes', async () => {
  await setAllowedRoots([home]);
  const sentinel = path.join(outside, 'sentinel.txt');
  const beforeBytes = await fs.readFile(sentinel);
  assert.deepEqual(beforeBytes, OUTSIDE_BYTES);
  await assert.rejects(writeFile(sentinel, 'MUTATED'), /Path not allowed/);
  assert.deepEqual(await fs.readFile(sentinel), beforeBytes);
  const target = path.join(outside, 'forbidden-directory');
  await assert.rejects(createDirectory(target), /Path not allowed/);
  await assert.rejects(fs.stat(target), { code: 'ENOENT' });
});