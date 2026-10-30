import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Verify process-local test configuration BEFORE importing any production
// singleton. The installed JDC configuration must never be read or mutated.
const expected = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR &&
    resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  expected,
  'E_TEST_ISOLATION_REQUIRED: use the repository test config preloader',
);
const { configManager } = await import('../dist/config-manager.js');
const { searchManager, stopSearchManagerCleanup } =
  await import('../dist/search-manager.js');
const {
  handleGetMoreSearchResults, handleListSearches,
} = await import('../dist/handlers/search-handlers.js');

async function withLiveSession(mode, check) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-search-revoke-'));
  const allowed = join(root, 'allowed');
  const outside = join(root, 'outside.txt');
  await mkdir(allowed);
  await writeFile(join(allowed, 'private-needle.txt'), 'PRIVATE_139_CONTENT');
  await writeFile(outside, 'OUTSIDE_BYTES_PRESERVED');
  const previous = configManager.getAllowedDirectoriesForFilesystem;
  let policy = 'unrestricted';
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (policy === 'failed') throw Error('test-only policy read outage');
    if (policy === 'unset') return undefined;
    return policy === 'restricted' ? [allowed] : [];
  };
  try {
    const created = await searchManager.startSearch({
      rootPath: allowed,
      searchType: 'files',
      pattern: 'private-needle.txt',
    });
    assert.ok(created.sessionId.startsWith('search_'));
    await check({
      sessionId: created.sessionId,
      revoke() { policy = mode; },
    });
    assert.equal(await readFile(outside, 'utf8'), 'OUTSIDE_BYTES_PRESERVED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = previous;
    for (const session of searchManager.listSearchSessions()) {
      searchManager.terminateSearch(session.id);
    }
    // Stop the existing search timer in this isolated test process.
    stopSearchManagerCleanup();
    searchManager.sessions?.clear?.();
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unset', 'failed']) {
  test(`T011 #139 ${mode} revokes already started MCP search results`, async () => {
    await withLiveSession(mode, async ({ sessionId, revoke }) => {
      const before = await handleListSearches();
      assert.notEqual(before.isError, true);
      assert.match(before.content[0].text, /private-needle.txt/);

      revoke();

      const subsequentResults = await handleGetMoreSearchResults({
        sessionId, offset: 0, length: 50,
      });
      assert.equal(subsequentResults.isError, true,
        'Reusing an existing session after policy loss must deny');
      assert.match(subsequentResults.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(subsequentResults.content[0].text, /private-needle.txt|PRIVATE_139_CONTENT/);

      const listed = await handleListSearches();
      assert.equal(listed.isError, true,
        'Policy loss must not reveal previous search-session metadata');
      assert.match(listed.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(listed.content[0].text, /private-needle.txt|PRIVATE_139_CONTENT/);

      assert.equal(
        searchManager.listSearchSessions().some(s => s.id === sessionId), false,
        'Denied search sessions must be terminated and erased',
      );
    });
  });
}

test('T011 #139 retained unrestricted policy preserves search continuation', async () => {
  await withLiveSession('unrestricted', async ({ sessionId }) => {
    const response = await handleGetMoreSearchResults({
      sessionId, offset: 0, length: 50,
    });
    assert.notEqual(response.isError, true);
    assert.match(response.content[0].text, /Search session:/);
    const listed = await handleListSearches();
    assert.notEqual(listed.isError, true);
    assert.match(listed.content[0].text, /private-needle.txt/);
  });
});
