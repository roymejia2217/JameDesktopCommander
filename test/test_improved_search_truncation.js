import assert from 'node:assert/strict';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

test('real streaming search preserves every match across bounded pages', async () => {
  // This is an unrestricted-search fixture, not a test of first-run config
  // creation or of the contents of the developer's checkout.
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dc-search-truncation-'));
  const previousConfig = process.env.DESKTOP_COMMANDER_CONFIG_DIR;
  const configDir = path.join(root, 'config');
  process.env.DESKTOP_COMMANDER_CONFIG_DIR = configDir;
  let configManager;
  let searchManager;
  let stopSearchManagerCleanup;
  let sessionId;
  try {
    await fs.mkdir(configDir);
    await fs.writeFile(path.join(configDir, 'config.json'), JSON.stringify({
      allowedDirectories: [], telemetryEnabled: false,
      welcomeOnboardingEligible: false, pendingWelcomeOnboarding: false,
    }), { flag: 'wx' });
    ({ configManager } = await import('../dist/config-manager.js'));
    ({ searchManager, stopSearchManagerCleanup } = await import('../dist/search-manager.js'));
    const { handleStartSearch, handleGetMoreSearchResults } =
      await import('../dist/handlers/search-handlers.js');
    assert.deepEqual(await configManager.getAllowedDirectoriesForFilesystem(), []);
    const fixture = path.join(root, 'fixture');
    await fs.mkdir(fixture);
    const count = 1201;
    const marker = 'JDC_SEARCH_PAGE_';
    const expected = Array.from({ length: count }, (_, i) =>
      marker + String(i + 1).padStart(4, '0'));
    await fs.writeFile(path.join(fixture, 'matches.txt'), expected.join('\n') + '\n');
    await fs.writeFile(path.join(fixture, 'nonmatch.txt'), 'unrelated content\n');

    const result = await handleStartSearch({
      path: fixture, pattern: marker + '[0-9]{4}', searchType: 'content',
      filePattern: '*.txt', contextLines: 0, maxResults: count + 1,
    });
    assert.notEqual(result.isError, true, result.content[0].text);
    sessionId = result.content[0].text.match(/^Started content search session: ([\w-]+)/)?.[1];
    assert.ok(sessionId, result.content[0].text);

    // Native close event, not a periodic result/status probe. Existing test
    // code accesses the manager's fixture sessions for deterministic cleanup.
    const session = searchManager.sessions.get(sessionId);
    assert.ok(session);
    if (!session.isComplete) {
      await once(session.process, 'close', { signal: AbortSignal.timeout(30_000) });
    }
    assert.equal(session.process.exitCode, 0, session.error);
    assert.equal(session.wasIncomplete, undefined);
    const received = [];
    for (const [offset, length] of [[0, 1000], [1000, 201]]) {
      const page = await handleGetMoreSearchResults({ sessionId, offset, length });
      const text = page.content[0].text;
      assert.notEqual(page.isError, true, text);
      assert.ok(Buffer.byteLength(text, 'utf8') <= 1024 * 1024);
      assert.match(text, /Status: COMPLETED/);
      assert.match(text, /Total results found: 1201 \(1201 matches\)/);
      assert.match(text, new RegExp('Showing results ' + offset + '-' + (offset + length - 1)));
      if (offset === 0) assert.match(text, /offset: 1000/);
      else assert.doesNotMatch(text, /More results available/);
      received.push(...Array.from(text.matchAll(/JDC_SEARCH_PAGE_[0-9]{4}/g), m => m[0]));
    }
    assert.deepEqual(received, expected, 'no lost, duplicate or reordered results');
    const tail = await handleGetMoreSearchResults({ sessionId, offset: -2 });
    assert.notEqual(tail.isError, true, tail.content[0].text);
    assert.deepEqual(Array.from(tail.content[0].text.matchAll(/JDC_SEARCH_PAGE_[0-9]{4}/g), m => m[0]),
      expected.slice(-2));
  } finally {
    if (searchManager && sessionId) {
      const session = searchManager.sessions.get(sessionId);
      if (session && !session.isComplete) {
        const closed = once(session.process, 'close', { signal: AbortSignal.timeout(5_000) });
        searchManager.terminateSearch(sessionId);
        await closed;
      }
      searchManager.sessions.delete(sessionId);
    }
    stopSearchManagerCleanup?.();
    await configManager?.close();
    if (previousConfig === undefined) delete process.env.DESKTOP_COMMANDER_CONFIG_DIR;
    else process.env.DESKTOP_COMMANDER_CONFIG_DIR = previousConfig;
    await fs.rm(root, { recursive: true, force: true });
  }
});
