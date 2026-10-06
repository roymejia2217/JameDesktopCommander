import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const LEGACY_KEY = '__nonblockingSaveRegressionTest';
const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'dc-config-hygiene-'));
const configPath = path.join(tempRoot, 'config.json');
let configManager;

mkdirSync(path.dirname(configPath), { recursive: true });
writeFileSync(
  configPath,
  JSON.stringify({
    telemetryEnabled: false,
    welcomeOnboardingEligible: false,
    pendingWelcomeOnboarding: false,
    customPluginState: { enabled: true },
    [LEGACY_KEY]: 99,
  }, null, 2),
);

try {
  const { ConfigManager } = await import('../dist/config-manager.js');
  configManager = new ConfigManager(configPath);

  const config = await configManager.getConfig();

  assert.equal(
    Object.hasOwn(config, LEGACY_KEY),
    false,
    'legacy regression-test key must be removed from in-memory config',
  );
  assert.deepEqual(
    config.customPluginState,
    { enabled: true },
    'unrelated custom config keys must be preserved',
  );

  const persisted = JSON.parse(readFileSync(configPath, 'utf8'));
  assert.equal(
    Object.hasOwn(persisted, LEGACY_KEY),
    false,
    'legacy regression-test key must be removed durably from disk',
  );
  assert.deepEqual(persisted.customPluginState, { enabled: true });

  console.log('Explicit config-path migration contract: PASS');
} finally {
  await configManager?.close();
  rmSync(tempRoot, { recursive: true, force: true });
}
