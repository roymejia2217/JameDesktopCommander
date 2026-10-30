import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// Never import persistent config before proving a per-process test config.
const expected = resolve(
  process.env.DESKTOP_COMMANDER_TEST_CONFIG_ROOT || '.tmp/test-config',
  String(process.pid),
);
assert.equal(
  process.env.DESKTOP_COMMANDER_CONFIG_DIR &&
    resolve(process.env.DESKTOP_COMMANDER_CONFIG_DIR),
  expected,
  'E_TEST_ISOLATION_REQUIRED: load the repository test preloader',
);

const { configManager } = await import('../dist/config-manager.js');
const { searchManager } = await import('../dist/search-manager.js');
const { searchFiles } = await import('../dist/tools/filesystem.js');
const { handleStartSearch } = await import('../dist/handlers/search-handlers.js');

async function fixture(mode, run) {
  const root = await mkdtemp(join(tmpdir(), 'jdc-t011-search-policy-'));
  const allowed = join(root, 'allowed');
  const privateFile = join(allowed, 'inside-private-139.txt');
  const outside = join(root, 'outside-sentinel.txt');
  await mkdir(allowed);
  await writeFile(privateFile, 'SEARCH_PRIVATE_MARKER_139');
  await writeFile(outside, 'EXTERNAL_BYTES_UNCHANGED');
  const original = configManager.getAllowedDirectoriesForFilesystem;
  const before = new Set(searchManager.listSearchSessions().map(s => s.id));
  configManager.getAllowedDirectoriesForFilesystem = async () => {
    if (mode === 'unavailable') throw Error('simulated policy outage');
    if (mode === 'unset') return undefined;
    return mode === 'restricted' ? [allowed] : [];
  };
  try {
    await run({ allowed, privateFile, outside });
    assert.equal(await readFile(outside, 'utf8'), 'EXTERNAL_BYTES_UNCHANGED');
  } finally {
    configManager.getAllowedDirectoriesForFilesystem = original;
    for (const session of searchManager.listSearchSessions()) {
      if (!before.has(session.id)) searchManager.terminateSearch(session.id);
    }
    await rm(root, { recursive: true, force: true });
  }
}

for (const mode of ['restricted', 'unset', 'unavailable']) {
  test(`T011 #139 ${mode} cannot start ripgrep or fallback filesystem search`, async () => {
    await fixture(mode, async ({ allowed, privateFile }) => {
      const sessionsBefore = searchManager.listSearchSessions().length;
      await assert.rejects(
        searchManager.startSearch({
          rootPath: allowed, pattern: 'SEARCH_PRIVATE_MARKER_139',
          searchType: 'content',
        }),
        /E_POLICY_UNAVAILABLE/,
      );
      assert.equal(searchManager.listSearchSessions().length, sessionsBefore,
        'Denied search must not spawn or register a process session');
      await assert.rejects(
        searchFiles(allowed, 'inside-private-139.txt'),
        /E_POLICY_UNAVAILABLE/,
      );
      const mcp = await handleStartSearch({
        path: allowed, pattern: 'SEARCH_PRIVATE_MARKER_139', searchType: 'content',
      });
      assert.equal(mcp.isError, true);
      assert.match(mcp.content[0].text, /E_POLICY_UNAVAILABLE/);
      assert.doesNotMatch(JSON.stringify(mcp), /SEARCH_PRIVATE_MARKER_139.*inside-private/);
      assert.equal(searchManager.listSearchSessions().length, sessionsBefore);
      assert.equal(await readFile(privateFile, 'utf8'), 'SEARCH_PRIVATE_MARKER_139');
    });
  });
}

test('T011 #139 explicit unrestricted search retains real positive results', async () => {
  await fixture('unrestricted', async ({ allowed }) => {
    const matching = await searchFiles(allowed, 'inside-private-139.txt');
    assert.ok(matching.some(name => name.endsWith('inside-private-139.txt')));
    const mcp = await handleStartSearch({
      path: allowed, pattern: 'inside-private-139.txt', searchType: 'files',
    });
    assert.notEqual(mcp.isError, true);
    assert.match(mcp.content[0].text, /Started file search session/);
  });
});
