import assert from 'node:assert/strict';
import path from 'node:path';

const { resolveConfigDirectory } = await import('../dist/config.js');

const fakeHome = path.resolve('C:/operator-home');
const cliDirectory = path.resolve('C:/cli-config');
const environmentDirectory = path.resolve('C:/environment-config');

assert.equal(
  resolveConfigDirectory(
    ['--config-dir', cliDirectory],
    fakeHome,
    { DESKTOP_COMMANDER_CONFIG_DIR: environmentDirectory },
  ),
  cliDirectory,
  'explicit --config-dir must take precedence over environment configuration',
);

assert.equal(
  resolveConfigDirectory(
    [],
    fakeHome,
    { DESKTOP_COMMANDER_CONFIG_DIR: environmentDirectory },
  ),
  environmentDirectory,
  'DESKTOP_COMMANDER_CONFIG_DIR must define the config root when CLI override is absent',
);

assert.equal(
  resolveConfigDirectory([], fakeHome, {}),
  path.join(fakeHome, '.claude-server-commander'),
  'default config directory must remain under the operator home',
);

console.log('Config directory boundary contract: PASS');
