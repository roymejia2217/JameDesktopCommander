import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createTelemetryIdentity, trackEvent } from '../setup-claude-server.js';
import { getConfigSettings } from '../uninstall-claude-server.js';

const uuid = '3ec70451-500b-44d5-a052-6dd4b8399999';
const secure = () => uuid;
const entropyFailure = () => { throw new Error('secure RNG unavailable'); };

test('setup only enables telemetry with a secure identifier', () => {
  assert.deepEqual(createTelemetryIdentity(secure), {
    clientId: uuid, telemetryEnabled: true,
  });
  assert.deepEqual(createTelemetryIdentity(entropyFailure), {
    clientId: 'unknown', telemetryEnabled: false,
  });
});

test('setup skips network telemetry when the secure generator fails', async () => {
  const identity = createTelemetryIdentity(entropyFailure);
  assert.equal(await trackEvent('entropy_unavailable', {}, identity), true);
});

test('uninstall uses only a secure identifier when config is absent', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-uninstall-id-'));
  try {
    const configPath = path.join(dir, 'does-not-exist.json');
    assert.deepEqual(await getConfigSettings({ configPath, generateId: secure }), {
      clientId: uuid, telemetryEnabled: false,
    });
    assert.deepEqual(await getConfigSettings({ configPath, generateId: entropyFailure }), {
      clientId: 'unknown', telemetryEnabled: false,
    });
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
test('uninstall preserves existing opt-in and disables it on RNG failure', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-uninstall-config-'));
  const configPath = path.join(dir, 'config.json');
  try {
    await fs.writeFile(configPath, JSON.stringify({
      clientId: 'existing-private-identifier', telemetryEnabled: true,
    }));
    assert.deepEqual(await getConfigSettings({ configPath, generateId: entropyFailure }), {
      clientId: 'existing-private-identifier', telemetryEnabled: true,
    });

    await fs.writeFile(configPath, JSON.stringify({ telemetryEnabled: true }));
    assert.deepEqual(await getConfigSettings({ configPath, generateId: secure }), {
      clientId: uuid, telemetryEnabled: true,
    });
    assert.deepEqual(await getConfigSettings({ configPath, generateId: entropyFailure }), {
      clientId: 'unknown', telemetryEnabled: false,
    });

    await fs.writeFile(configPath, '{ malformed-json');
    assert.deepEqual(await getConfigSettings({ configPath, generateId: secure }), {
      clientId: 'unknown', telemetryEnabled: false,
    });
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
