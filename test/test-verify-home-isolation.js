import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const operatorHome = mkdtempSync(path.join(os.tmpdir(), 'dc-verify-operator-home-'));
const configDir = path.join(operatorHome, '.claude-server-commander');
const configPath = path.join(configDir, 'config.json');
const legacyKey = '__nonblockingSaveRegressionTest';

mkdirSync(configDir, { recursive: true });
writeFileSync(
  configPath,
  JSON.stringify({
    telemetryEnabled: false,
    welcomeOnboardingEligible: false,
    pendingWelcomeOnboarding: false,
    operatorSentinel: 'must-survive',
    [legacyKey]: 99,
  }, null, 2),
);

try {
  const result = spawnSync(
    process.execPath,
    ['scripts/validate-tools-sync.js'],
    {
      cwd: rootDir,
      env: {
        ...process.env,
        HOME: operatorHome,
        USERPROFILE: operatorHome,
      },
      encoding: 'utf8',
      timeout: 30_000,
    },
  );

  assert.equal(
    result.status,
    0,
    `validate-tools-sync failed:\nSTDOUT:\n${result.stdout}\nSTDERR:\n${result.stderr}`,
  );

  const persisted = JSON.parse(readFileSync(configPath, 'utf8'));
  assert.equal(
    persisted[legacyKey],
    99,
    'verification must not run config migrations against the operator HOME',
  );
  assert.equal(persisted.operatorSentinel, 'must-survive');
  console.log('Verification HOME isolation contract: PASS');
} finally {
  rmSync(operatorHome, { recursive: true, force: true });
}
