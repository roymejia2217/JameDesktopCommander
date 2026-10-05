import assert from 'assert';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import os from 'os';
import path from 'path';

/**
 * Regression test for the parallel-load tool-call hang.
 *
 * Root cause: the CallTool handler awaited usageTracker.trackSuccess() before
 * returning any tool result; that chained through configManager.setValue ->
 * fs.writeFile on EVERY call. Under a saturated libuv threadpool (many parallel
 * reads stalled on a slow/cloud filesystem) the awaited write could not get a
 * thread, so even pure-memory tools (list_processes) hung until the client's
 * ~4-minute cap. Each call also fired an independent write of the same file,
 * risking a corrupted config.json.
 *
 * Fix: stats persist via configManager.setValueNonBlocking() — in-memory update
 * is synchronous, the disk write is coalesced and serialized on a single write
 * chain, and the caller never waits on it.
 *
 * This test is fast and cross-platform (no FIFO/python); the FIFO-based proof
 * that the response no longer blocks under a starved pool lives in test/repro/.
 *
 * The persistence test must never mutate the operator's real Desktop Commander
 * configuration. It therefore boots the compiled config singleton under an
 * isolated temporary home before importing any module that calls os.homedir().
 */

const KEY = '__nonblockingSaveRegressionTest';
const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const isolatedHome = mkdtempSync(path.join(os.tmpdir(), 'dc-nonblocking-config-save-'));
let passed = 0;

async function run() {
  process.env.HOME = isolatedHome;
  process.env.USERPROFILE = isolatedHome;

  const [{ configManager }, { CONFIG_FILE }] = await Promise.all([
    import('../dist/config-manager.js'),
    import('../dist/config.js'),
  ]);

  await configManager.getConfig();

  const BURST = 100;
  const t0 = Date.now();
  await Promise.all(
    Array.from({ length: BURST }, (_, i) => configManager.setValueNonBlocking(KEY, i))
  );
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 200, `burst of ${BURST} non-blocking saves took ${elapsed}ms (expected < 200ms)`);
  passed++;
  console.log(`✓ ${BURST} non-blocking saves resolved in ${elapsed}ms`);

  assert.strictEqual(await configManager.getValue(KEY), BURST - 1);
  passed++;
  console.log('✓ in-memory value reflects the latest write immediately');

  await configManager.flushPendingWrites();

  let parsed;
  assert.doesNotThrow(
    () => {
      parsed = JSON.parse(readFileSync(CONFIG_FILE, 'utf8'));
    },
    'config.json must remain valid JSON after concurrent writes'
  );
  assert.strictEqual(parsed[KEY], BURST - 1, 'final value must be persisted to disk');
  passed++;
  console.log('✓ config.json is valid and holds the coalesced final value');
}

function restoreEnvironment() {
  if (originalHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = originalHome;
  }

  if (originalUserProfile === undefined) {
    delete process.env.USERPROFILE;
  } else {
    process.env.USERPROFILE = originalUserProfile;
  }

  rmSync(isolatedHome, { recursive: true, force: true });
}

run()
  .then(() => {
    restoreEnvironment();
    console.log(`\nPASS (${passed}/3)`);
    process.exit(0);
  })
  .catch((error) => {
    restoreEnvironment();
    console.error(`\nFAIL: ${error.message}`);
    process.exit(1);
  });
