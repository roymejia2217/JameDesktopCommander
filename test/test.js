import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const ORIGINAL_TEXT = Buffer.from('This is old content to replace.\r\nTail unchanged.\r\n');
const OUTSIDE_TEXT = Buffer.from('Protected outside-root bytes.\r\n');
const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
let root;
let outsideRoot;
let filePath;
let outsidePath;
let originalConfig;
let configManager;
let handleEditBlock;

before(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-basic-edit-'));
  outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-basic-edit-outside-'));
  // Dynamic imports keep both the application config and fuzzy logs isolated.
  process.env.HOME = root;
  process.env.USERPROFILE = root;
  assert.equal(path.resolve(os.homedir()), path.resolve(root));
  ({ configManager } = await import('../dist/config-manager.js'));
  ({ handleEditBlock } = await import('../dist/handlers/edit-search-handlers.js'));
  originalConfig = await configManager.getConfig();
  filePath = path.join(root, 'edit-target.txt');
  outsidePath = path.join(outsideRoot, 'outside-target.txt');
  await configManager.setValue('allowedDirectories', [root]);
});

beforeEach(async () => {
  await fs.writeFile(filePath, ORIGINAL_TEXT);
  await fs.writeFile(outsidePath, OUTSIDE_TEXT);
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
    try {
      if (root) await fs.rm(root, { recursive: true, force: true });
    } finally {
      if (outsideRoot) await fs.rm(outsideRoot, { recursive: true, force: true });
    }
  }
});

function responseText(result) {
  assert.equal(result.content?.[0]?.type, 'text');
  assert.equal(typeof result.content[0].text, 'string');
  return result.content[0].text;
}

test('basic edit replaces a single exact substring and preserves surrounding bytes', async () => {
  const result = await handleEditBlock({
    file_path: filePath, old_string: 'old content',
    new_string: 'new content', expected_replacements: 1,
  });
  assert.match(responseText(result), /new content/);
  assert.deepEqual(await fs.readFile(filePath),
    Buffer.from('This is new content to replace.\r\nTail unchanged.\r\n'));
});

test('basic edit does not write when the substring is absent', async () => {
  const beforeBytes = await fs.readFile(filePath);
  const result = await handleEditBlock({
    file_path: filePath, old_string: 'UNMATCHED_BASIC_EDIT_SEQUENCE_84297',
    new_string: 'Should not write', expected_replacements: 1,
  });
  assert.match(responseText(result), /Search content not found/i);
  assert.deepEqual(await fs.readFile(filePath), beforeBytes);
});

test('basic edit does not write when the expected replacement count is wrong', async () => {
  const beforeBytes = await fs.readFile(filePath);
  const result = await handleEditBlock({
    file_path: filePath, old_string: 'old content',
    new_string: 'Should not write', expected_replacements: 2,
  });
  assert.match(responseText(result), /Expected 2 occurrences but found 1/i);
  assert.deepEqual(await fs.readFile(filePath), beforeBytes);
});

test('basic edit denies an outside-root file and preserves its bytes', async () => {
  const beforeBytes = await fs.readFile(outsidePath);
  const result = await handleEditBlock({
    file_path: outsidePath, old_string: 'Protected',
    new_string: 'Should not write', expected_replacements: 1,
  });
  assert.match(responseText(result), /Access denied|not allowed|outside/i);
  assert.deepEqual(await fs.readFile(outsidePath), beforeBytes);
});
