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
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'jdc-inspector-contract-'));
const runtimeConfigDir = path.join(tempRoot, 'runtime');
const runtimeConfigPath = path.join(runtimeConfigDir, 'config.json');
const inspectorConfigPath = path.join(tempRoot, 'inspector.json');
const require = createRequire(import.meta.url);
const legacyKey = '__nonblockingSaveRegressionTest';

mkdirSync(runtimeConfigDir, { recursive: true });

const originalRuntimeConfig = JSON.stringify(
  {
    telemetryEnabled: false,
    welcomeOnboardingEligible: false,
    pendingWelcomeOnboarding: false,
    operatorSentinel: 'must-survive',
    [legacyKey]: 99,
  },
  null,
  2,
);
writeFileSync(runtimeConfigPath, originalRuntimeConfig);

const inspectorPackagePath = require.resolve(
  '@modelcontextprotocol/inspector/package.json',
);
const inspectorPackage = JSON.parse(readFileSync(inspectorPackagePath, 'utf8'));
const inspectorLauncher = path.resolve(
  path.dirname(inspectorPackagePath),
  inspectorPackage.bin['mcp-inspector'],
);

writeFileSync(
  inspectorConfigPath,
  JSON.stringify(
    {
      mcpServers: {
        jdc: {
          type: 'stdio',
          command: process.execPath,
          args: [
            path.join(rootDir, 'dist', 'index.js'),
            '--config-dir',
            runtimeConfigDir,
            '--no-onboarding',
          ],
          cwd: rootDir,
          env: {
            DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
            DC_FLAG_URL: 'http://127.0.0.1:9/',
          },
        },
      },
    },
    null,
    2,
  ),
);

function runInspector(methodArgs) {
  return spawnSync(
    process.execPath,
    [
      inspectorLauncher,
      '--cli',
      '--config',
      inspectorConfigPath,
      '--server',
      'jdc',
      ...methodArgs,
      '--format',
      'json',
    ],
    {
      cwd: rootDir,
      encoding: 'utf8',
      timeout: 30_000,
    },
  );
}

try {
  const listResult = runInspector([
    '--method',
    'tools/list',
    '--strict',
  ]);

  assert.equal(
    listResult.status,
    0,
    `Inspector tools/list failed:\nSTDOUT:\n${listResult.stdout}\nSTDERR:\n${listResult.stderr}`,
  );

  const inspection = JSON.parse(listResult.stdout);
  const serverTools = inspection.result.tools
    .map((tool) => tool.name)
    .sort();

  const manifest = JSON.parse(
    readFileSync(path.join(rootDir, 'manifest.template.json'), 'utf8'),
  );
  const manifestTools = manifest.tools
    .map((tool) => tool.name)
    .sort();

  assert.deepEqual(
    serverTools,
    manifestTools,
    'MCPB manifest tools must exactly match Inspector tools/list',
  );
  assert.equal(
    readFileSync(runtimeConfigPath, 'utf8'),
    originalRuntimeConfig,
    'MCP initialize/tools-list must not mutate Desktop Commander config',
  );

  const callResult = runInspector([
    '--method',
    'tools/call',
    '--tool-name',
    'get_config',
  ]);

  assert.equal(
    callResult.status,
    0,
    `Inspector get_config failed:\nSTDOUT:\n${callResult.stdout}\nSTDERR:\n${callResult.stderr}`,
  );

  const migratedConfig = JSON.parse(readFileSync(runtimeConfigPath, 'utf8'));
  assert.equal(
    Object.hasOwn(migratedConfig, legacyKey),
    false,
    'first operational tool call must run config migration',
  );
  assert.equal(
    migratedConfig.operatorSentinel,
    'must-survive',
    'operational initialization must preserve unrelated config',
  );

  console.log(
    `MCP Inspector contract: PASS (${serverTools.length} tools, pure listing, lazy operational init)`,
  );
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
