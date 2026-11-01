import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { handleEditBlock } from '../dist/handlers/edit-search-handlers.js';
import { configManager } from '../dist/config-manager.js';

async function withEditFixture(allowedDirectories, check) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-edit-smoke-'));
  const file = join(root, 'test.txt');
  const originalConfig = await configManager.getConfig();
  try {
    await writeFile(file, 'This is old content to replace');
    await configManager.setValue('allowedDirectories', allowedDirectories(root));
    const result = await handleEditBlock({
      file_path: file,
      old_string: 'old content',
      new_string: 'new content',
      expected_replacements: 1,
    });
    await check(result, await readFile(file, 'utf8'));
  } finally {
    try {
      await configManager.updateConfig(originalConfig);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
}

test('restricted edit fails closed and preserves original text', async () => {
  await withEditFixture((root) => [root], async (result, content) => {
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /E_POLICY_UNAVAILABLE/);
    assert.equal(content, 'This is old content to replace');
  });
});

test('explicit unrestricted edit replaces the requested text', async () => {
  await withEditFixture(() => [], async (result, content) => {
    assert.notEqual(result.isError, true, result.content[0].text);
    assert.equal(content, 'This is new content to replace');
  });
});
