import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const LEGACY_KEY = '__nonblockingSaveRegressionTest';
const originalHome = process.env.HOME;
const originalUserProfile = process.env.USERPROFILE;
const isolatedHome = mkdtempSync(path.join(os.tmpdir(), 'dc-config-hygiene-'));
const configDir = path.join(isolatedHome, '.claude-server-commander');
const configPath = path.join(configDir, 'config.json');

mkdirSync(configDir, { recursive: true });
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

process.env.HOME = isolatedHome;
process.env.USERPROFILE = isolatedHome;

async function run() {
  const [{ configManager }, { CONFIG_FILE }] = await Promise.all([
    import('../dist/config-manager.js'),
    import('../dist/config.js'),
  ]);

  assert.equal(CONFIG_FILE, configPath, 'test must use only the isolated config path');

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
}

function cleanup() {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;

  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;

  rmSync(isolatedHome, { recursive: true, force: true });
}

try {
  await run();
  console.log('Legacy config test-artifact cleanup contract: PASS');
} finally {
  cleanup();
}
