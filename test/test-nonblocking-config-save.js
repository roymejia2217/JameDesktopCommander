import assert from 'assert';
import { mkdtempSync, readFileSync, rmSync } from 'fs';
import os from 'os';
import path from 'path';

/**
 * Regression test for the parallel-load tool-call hang.
 *
 * The persistence contract is exercised through an explicitly injected config
 * path. Tests must never rely on mutating HOME/USERPROFILE to redirect
 * production state.
 */

const KEY = '__nonblockingSaveRegressionTest';
const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'dc-nonblocking-config-save-'));
const configPath = path.join(tempRoot, 'config.json');
let passed = 0;
let configManager;

async function run() {
  const { ConfigManager } = await import('../dist/config-manager.js');
  configManager = new ConfigManager(configPath);

  await configManager.getConfig();

  const BURST = 100;
  const t0 = Date.now();
  await Promise.all(
    Array.from({ length: BURST }, (_, i) => configManager.setValueNonBlocking(KEY, i)),
  );
  const elapsed = Date.now() - t0;
  assert.ok(
    elapsed < 200,
    `burst of ${BURST} non-blocking saves took ${elapsed}ms (expected < 200ms)`,
  );
  passed++;
  console.log(`✓ ${BURST} non-blocking saves resolved in ${elapsed}ms`);

  assert.strictEqual(await configManager.getValue(KEY), BURST - 1);
  passed++;
  console.log('✓ in-memory value reflects the latest write immediately');

  await configManager.flushPendingWrites();

  let parsed;
  assert.doesNotThrow(
    () => {
      parsed = JSON.parse(readFileSync(configPath, 'utf8'));
    },
    'config.json must remain valid JSON after concurrent writes',
  );
  assert.strictEqual(parsed[KEY], BURST - 1, 'final value must be persisted to disk');
  passed++;
  console.log('✓ config.json is valid and holds the coalesced final value');
}

try {
  await run();
  console.log(`\nPASS (${passed}/3)`);
} finally {
  await configManager?.close();
  rmSync(tempRoot, { recursive: true, force: true });
}
