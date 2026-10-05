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
const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-ui-boundary-'));
const previewImage = path.join(isolatedHome, 'pixel.png');
await fs.writeFile(
  previewImage,
  Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl9sAAAAASUVORK5CYII=', 'base64'),
);

const client = new Client(
  { name: 'jdc-ui-boundary-test', version: '1.0.0' },
  { capabilities: {} },
);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint],
  env: { ...process.env, HOME: isolatedHome, USERPROFILE: isolatedHome },
});

await client.connect(transport);
try {
  const allowed = await client.callTool({
    name: 'set_config_value',
    arguments: { key: 'allowedDirectories', value: [isolatedHome], origin: 'llm' },
  });
  assert.ok(!allowed.isError, 'isolated test directory should be allowed');

  const { tools } = await client.listTools();
  const byName = new Map(tools.map((tool) => [tool.name, tool]));

  const widgetDataTools = [
    'get_config',
    'set_config_value',
    'read_file',
    'write_file',
    'list_directory',
    'edit_block',
  ];

  for (const name of widgetDataTools) {
    const tool = byName.get(name);
    assert.ok(tool, `missing data/action tool: ${name}`);
    assert.equal(tool._meta?.['ui/resourceUri'], undefined, `${name} must not mount UI`);
    assert.equal(tool._meta?.['openai/outputTemplate'], undefined, `${name} must not mount UI`);
    assert.equal(tool._meta?.ui?.resourceUri, undefined, `${name} must not mount UI`);
    assert.equal(tool._meta?.['openai/widgetAccessible'], true, `${name} must remain widget-accessible`);
  }

  const renderTools = new Map([
    ['preview_file', 'ui://desktop-commander/file-preview'],
    ['render_directory', 'ui://desktop-commander/file-preview'],
    ['render_config_editor', 'ui://desktop-commander/config-editor'],
  ]);

  for (const [name, resourceUri] of renderTools) {
    const tool = byName.get(name);
    assert.ok(tool, `missing explicit render tool: ${name}`);
    assert.equal(tool._meta?.['ui/resourceUri'], resourceUri);
    assert.equal(tool._meta?.['openai/outputTemplate'], resourceUri);
    assert.equal(tool._meta?.ui?.resourceUri, resourceUri);
  }

  const preview = await client.callTool({
    name: 'preview_file',
    arguments: { path: previewImage },
  });
  assert.ok(!preview.isError, 'preview_file should read the selected file');
  assert.ok(preview.content?.some((item) => item.type === 'image'), 'preview_file must preserve model image content');
  assert.equal(preview.structuredContent, undefined, 'preview_file must not leak widget pull payload to the model');

  const directory = await client.callTool({
    name: 'render_directory',
    arguments: { path: isolatedHome, depth: 1 },
  });
  assert.ok(!directory.isError, 'render_directory should list the selected directory');
  assert.match(directory.content?.[0]?.text ?? '', /pixel\.png/);
  assert.equal(directory.structuredContent, undefined, 'render_directory must preserve model-facing list semantics');

  const configEditor = await client.callTool({ name: 'render_config_editor', arguments: {} });
  assert.ok(configEditor.structuredContent?.config, 'render_config_editor should provide config state');

  console.log('UI render boundary contract: PASS');
} finally {
  await client.close();
  await fs.rm(isolatedHome, { recursive: true, force: true });
}
