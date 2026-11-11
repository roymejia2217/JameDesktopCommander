import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const REPEATING = [
  'This is a repeating line.',
  'This is a unique line.',
  'This is a repeating line.',
  'This is another unique line.',
  'This is a repeating line.',
  'One more unique line.',
  'This is a repeating line.',
].join('\n');

const CONTEXT = [
  'Header section',
  'This is a target line.',
  'End of header section',
  '',
  'Main content section',
  'This is a target line.',
  'More content here',
  'This is a target line.',
  'End of main content',
  '',
  'Footer section',
  'This is a target line.',
  'End of footer',
].join('\n');

const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
let root;
let multiPath;
let contextPath;
let originalConfig;
let configManager;
let handleEditBlock;

before(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-edit-block-'));
  // The fuzzy-search logger derives its location from os.homedir() at import.
  // Keep logs and config isolated from the installed user's runtime.
  process.env.HOME = root;
  process.env.USERPROFILE = root;
  assert.equal(path.resolve(os.homedir()), path.resolve(root));
  ({ configManager } = await import('../dist/config-manager.js'));
  ({ handleEditBlock } = await import('../dist/handlers/edit-search-handlers.js'));
  originalConfig = await configManager.getConfig();
  multiPath = path.join(root, 'multiple_occurrences.txt');
  contextPath = path.join(root, 'context_test.txt');
  await configManager.setValue('allowedDirectories', [root]);
});

beforeEach(async () => {
  await fs.writeFile(multiPath, REPEATING);
  await fs.writeFile(contextPath, CONTEXT);
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
    if (root) await fs.rm(root, { recursive: true, force: true });
  }
});

function responseText(result) {
  assert.equal(result.content?.[0]?.type, 'text');
  assert.equal(typeof result.content[0].text, 'string');
  return result.content[0].text;
}

test('edit_block rejects too few expected matches without changing bytes', async () => {
  const beforeBytes = await fs.readFile(multiPath);
  const result = await handleEditBlock({
    file_path: multiPath, old_string: 'This is a repeating line.',
    new_string: 'Should not write', expected_replacements: 1,
  });
  assert.match(responseText(result), /Expected 1 occurrences but found 4/);
  assert.deepEqual(await fs.readFile(multiPath), beforeBytes);
});

test('edit_block rejects too many expected matches without changing bytes', async () => {
  const beforeBytes = await fs.readFile(multiPath);
  const result = await handleEditBlock({
    file_path: multiPath, old_string: 'This is another unique line.',
    new_string: 'Should not write', expected_replacements: 3,
  });
  assert.match(responseText(result), /Expected 3 occurrences but found 1/);
  assert.deepEqual(await fs.readFile(multiPath), beforeBytes);
});

test('edit_block replaces exactly four occurrences', async () => {
  const result = await handleEditBlock({
    file_path: multiPath, old_string: 'This is a repeating line.',
    new_string: 'Replaced exactly', expected_replacements: 4,
  });
  assert.match(responseText(result), /Replaced exactly/);
  assert.deepEqual(await fs.readFile(multiPath),
    Buffer.from(REPEATING.replaceAll('This is a repeating line.', 'Replaced exactly')));
});

test('edit_block edits header and footer without changing the middle', async () => {
  const header = await handleEditBlock({
    file_path: contextPath, old_string: 'Header section\nThis is a target line.',
    new_string: 'Header section\nModified header.', expected_replacements: 1,
  });
  assert.match(responseText(header), /Modified header/);
  const footer = await handleEditBlock({
    file_path: contextPath, old_string: 'Footer section\nThis is a target line.',
    new_string: 'Footer section\nModified footer.', expected_replacements: 1,
  });
  assert.match(responseText(footer), /Modified footer/);
  const expected = CONTEXT
    .replace('Header section\nThis is a target line.', 'Header section\nModified header.')
    .replace('Footer section\nThis is a target line.', 'Footer section\nModified footer.');
  assert.deepEqual(await fs.readFile(contextPath), Buffer.from(expected));
});

test('edit_block refuses an absent pattern without changing bytes', async () => {
  const beforeBytes = await fs.readFile(contextPath);
  const result = await handleEditBlock({
    file_path: contextPath, old_string: 'ZZZZZZZZ_NOT_IN_THIS_FILE_4590',
    new_string: 'Should not write', expected_replacements: 1,
  });
  assert.match(responseText(result), /Search content not found/);
  assert.deepEqual(await fs.readFile(contextPath), beforeBytes);
});

test('edit_block refuses an empty search without changing bytes', async () => {
  const beforeBytes = await fs.readFile(contextPath);
  await assert.rejects(
    () => handleEditBlock({
      file_path: contextPath, old_string: '',
      new_string: 'Should not write', expected_replacements: 1,
    }),
    error => error?.name === 'ZodError' && error.issues?.some(
      issue => issue.code === 'custom' &&
        issue.message === 'Must provide either (old_string + new_string) or (range + content)'),
    'the input schema must reject an empty old_string before filesystem I/O',
  );
  assert.deepEqual(await fs.readFile(contextPath), beforeBytes);
});
