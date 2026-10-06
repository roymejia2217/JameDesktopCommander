#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.resolve(testDirectory, '..', 'dist', 'index.js');
const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-computer-tool-'));

const client = new Client(
  { name: 'jdc-computer-tool-contract', version: '1.0.0' },
  { capabilities: {} },
);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint],
  env: {
    ...process.env,
    DESKTOP_COMMANDER_CONFIG_DIR: path.join(isolatedHome, '.claude-server-commander'),
  },
});

await client.connect(transport);
try {
  const { tools } = await client.listTools();
  const tool = tools.find((candidate) => candidate.name === 'computer_inspect');

  assert.ok(tool, 'computer_inspect must be exposed by the MCP server');
  assert.equal(tool.annotations?.readOnlyHint, true);
  assert.equal(tool.annotations?.destructiveHint, false);
  assert.equal(tool.annotations?.idempotentHint, true);
  assert.equal(tool.annotations?.openWorldHint, false);
  assert.equal(tool._meta?.['ui/resourceUri'], undefined, 'computer_inspect must not mount UI');
  assert.deepEqual(tool.inputSchema?.properties?.action?.enum, ['health', 'snapshot']);

  const rejected = await client.callTool({
    name: 'computer_inspect',
    arguments: { action: 'click' },
  });
  assert.equal(rejected.isError, true, 'unsupported computer actions must fail closed');
  assert.equal(rejected.structuredContent?.error?.code, 'INVALID_INPUT');

  console.log('Computer inspect server contract: PASS');
} finally {
  await client.close();
  await fs.rm(isolatedHome, { recursive: true, force: true });
}
