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
const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-tool-selection-'));

const client = new Client(
  { name: 'jdc-tool-selection-test', version: '1.0.0' },
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
  const byName = new Map(tools.map((tool) => [tool.name, tool]));

  const description = (name) => {
    const tool = byName.get(name);
    assert.ok(tool, 'missing tool: ' + name);
    assert.equal(typeof tool.description, 'string', 'missing description for ' + name);
    return tool.description.replace(/\s+/g, ' ').trim();
  };

  const readFile = description('read_file');
  assert.match(
    readFile,
    /For two or more already-known file paths, prefer read_multiple_files instead of issuing separate read_file calls\./,
    'read_file must redirect multi-file analysis to read_multiple_files',
  );
  assert.match(
    readFile,
    /This tool is for model analysis and does not mount a Presentation widget\./,
    'read_file must make the no-Presentation boundary explicit',
  );

  const readMultipleFiles = description('read_multiple_files');
  assert.match(
    readMultipleFiles,
    /Prefer this tool when two or more file paths are already known\./,
    'read_multiple_files must be the preferred known-path batching tool',
  );
  assert.match(
    readMultipleFiles,
    /One MCP call batches those reads and reduces remote round-trips\./,
    'read_multiple_files must explain the batching benefit',
  );
  assert.match(
    readMultipleFiles,
    /This tool is for model analysis and does not mount a Presentation widget\./,
    'read_multiple_files must make the no-Presentation boundary explicit',
  );

  const renderWorkspace = description('render_workspace');
  assert.match(
    renderWorkspace,
    /Do not call render_workspace merely because the model needs file contents\./,
    'render_workspace must reject model-only inspection as a reason to mount UI',
  );
  assert.match(
    renderWorkspace,
    /Use offset and length to render only the relevant range when full-file visualization is unnecessary\./,
    'render_workspace must advertise partial visual review',
  );

  console.log('Tool-selection batching contract: PASS');
} finally {
  await client.close();
  await fs.rm(isolatedHome, { recursive: true, force: true });
}
