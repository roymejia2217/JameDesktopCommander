import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const expected = resolve(process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config', String(process.pid));
assert.equal(resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR || ''), expected,
  'E_TEST_ISOLATION_REQUIRED: use the repository test preloader');

const { configManager } = await import('../dist/config-manager.js');
const { searchManager, stopSearchManagerCleanup } = await import('../dist/search-manager.js');
const { searchFiles } = await import('../dist/tools/filesystem.js');
const { handleStartSearch } = await import('../dist/handlers/search-handlers.js');

after(async () => {
  stopSearchManagerCleanup();
  searchManager.sessions?.clear?.();
  await configManager.close();
});

async function withSearchPolicy(policy, fn) {
  const dir = await mkdtemp(join(tmpdir(), 'jdc-t011-search-authority-'));
  const allowed = join(dir, 'allowed');
  const inside = join(allowed, 'inside-private.txt');
  const outside = join(dir, 'outside-sentinel.txt');
  await mkdir(allowed);
  await writeFile(inside, 'INSIDE_SEARCH_MARKER_139');
  await writeFile(outside, 'EXTERIOR_UNCHANGED_139');
  const previous = configManager.getAllowedDirectoriesForFilesystem;
  const before = new Set(searchManager.listSearchSessions().map(s => s.id));
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (policy === 'outage') throw new Error('injected unavailable policy');
    if (policy === 'missing') return undefined;
    return policy === 'restricted' ? [allowed] : [];
  };
  try {
    await fn({ allowed, inside, outside, before });
    assert.equal(await readFile(outside, 'utf8'), 'EXTERIOR_UNCHANGED_139');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = previous;
    for (const session of searchManager.listSearchSessions()) {
      if (!before.has(session.id)) searchManager.terminateSearch(session.id);
    }
    stopSearchManagerCleanup();
    searchManager.sessions?.clear?.();
    await rm(dir, { recursive: true, force: true });
  }
}

for (const policy of ['restricted', 'missing', 'outage']) {
  test(`T011 #139 ${policy}: refuse ripgrep, Node fallback and MCP search without authority`, async () => {
    await withSearchPolicy(policy, async ({ allowed, before }) => {
      const args = { rootPath: allowed, pattern: 'INSIDE_SEARCH_MARKER_139', searchType: 'content' };
      await assert.rejects(searchManager.startSearch(args), /E_POLICY_UNAVAILABLE/);
      assert.equal(searchManager.listSearchSessions().length, before.size);
      await assert.rejects(searchFiles(allowed, 'inside-private.txt'), /E_POLICY_UNAVAILABLE/);
      assert.equal(searchManager.listSearchSessions().length, before.size);
      const response = await handleStartSearch({
        path: allowed, pattern: 'INSIDE_SEARCH_MARKER_139', searchType: 'content',
      });
      assert.equal(response.isError, true);
      assert.match(response.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(JSON.stringify(response), /INSIDE_SEARCH_MARKER_139.*inside-private/);
      assert.equal(searchManager.listSearchSessions().length, before.size);
    });
  });
}

test('T011 #139 explicit empty allowlist retains ordinary unrestricted search', async () => {
  await withSearchPolicy('unrestricted', async ({ allowed }) => {
    const result = await searchManager.startSearch({
      rootPath: allowed, pattern: 'inside-private.txt', searchType: 'files',
    });
    assert.match(result.sessionId, /^search_/);
    assert.equal(result.isError, false);
  });
});
