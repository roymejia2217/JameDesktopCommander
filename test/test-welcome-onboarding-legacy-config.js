/**
 * Regression contract for legacy pending welcome onboarding.
 *
 * MCP initialize and tools/list are introspection boundaries and must not
 * mutate persistent configuration. The first operational tools/call performs
 * runtime initialization and must consume legacy pending onboarding for
 * clients that must never receive a retroactive welcome page.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.resolve(testDirectory, '..', 'dist', 'index.js');

async function runScenario(name, config, featureFlags) {
  const configDir = mkdtempSync(path.join(os.tmpdir(), 'dc-welcome-legacy-'));
  const configPath = path.join(configDir, 'config.json');
  mkdirSync(configDir, { recursive: true });
  writeFileSync(configPath, JSON.stringify(config));

  if (featureFlags) {
    writeFileSync(
      path.join(configDir, 'feature-flags.json'),
      JSON.stringify({ version: 'test', flags: featureFlags }),
    );
  }

  const client = new Client(
    { name: 'claude-code', version: 'test' },
    { capabilities: {} },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, '--config-dir', configDir, '--no-onboarding'],
    cwd: path.dirname(entrypoint),
    env: {
      ...process.env,
      DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
      DC_FLAG_URL: 'http://127.0.0.1:9/',
    },
    stderr: 'pipe',
  });

  try {
    await client.connect(transport);

    const afterInitialize = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(
      afterInitialize.pendingWelcomeOnboarding,
      true,
      `${name}: MCP initialize must remain side-effect free`,
    );

    await client.listTools();
    const afterList = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(
      afterList.pendingWelcomeOnboarding,
      true,
      `${name}: tools/list must remain side-effect free`,
    );

    const result = await client.callTool({
      name: 'get_config',
      arguments: {},
    });
    assert.notEqual(result.isError, true, `${name}: get_config must succeed`);

    const resultConfig = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.equal(
      resultConfig.pendingWelcomeOnboarding,
      false,
      `${name}: first operational tool call must consume pending welcome onboarding`,
    );
    assert.equal(
      resultConfig.sawOnboardingPage,
      undefined,
      `${name}: skip path must resolve before the A/B decision`,
    );

    console.log(`✓ ${name}`);
  } finally {
    await client.close().catch(() => {});
    rmSync(configDir, { recursive: true, force: true });
  }
}

await runScenario(
  'Legacy Claude Code config does not retain pending welcome onboarding',
  { telemetryEnabled: false, pendingWelcomeOnboarding: true },
);

await runScenario(
  'Disabled welcome-page feature flag consumes pending onboarding',
  {
    telemetryEnabled: false,
    welcomeOnboardingEligible: true,
    pendingWelcomeOnboarding: true,
  },
  { welcome_page_enabled: false },
);

await runScenario(
  'Configured Claude Code exclusion matches case-insensitively',
  {
    telemetryEnabled: false,
    welcomeOnboardingEligible: true,
    pendingWelcomeOnboarding: true,
  },
  {
    welcome_page_enabled: true,
    welcome_page_excluded_clients: ['CLAUDE-CODE'],
  },
);
