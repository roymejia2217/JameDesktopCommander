#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
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

function findAssignedHandler(source, handlerName) {
  let handler;
  const visit = (node) => {
    if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isPropertyAccessExpression(node.left)
      && node.left.name.text === handlerName
    ) {
      handler = node.right;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return handler;
}

function getAssignedHandlerCalls(sourceText, handlerName) {
  const source = ts.createSourceFile('app.ts', sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const handler = findAssignedHandler(source, handlerName);
  const calls = [];
  if (!handler) return calls;

  const scan = (node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      calls.push(node.expression.text);
    }
    ts.forEachChild(node, scan);
  };
  scan(handler);
  return calls;
}

function directPayloadDeliveryRejectsMutations(sourceText) {
  const source = ts.createSourceFile('app.ts', sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const handler = findAssignedHandler(source, 'ontoolresult');
  if (!handler) return false;

  let guarded = false;
  const containsDirectDelivery = (node) => {
    let found = false;
    const scan = (child) => {
      if (
        ts.isCallExpression(child)
        && ts.isIdentifier(child.expression)
        && child.expression.text === 'deliver'
        && child.arguments.some((arg) => ts.isIdentifier(arg) && arg.text === 'directPayload')
      ) {
        found = true;
      }
      ts.forEachChild(child, scan);
    };
    scan(node);
    return found;
  };
  const conditionRejectsMutation = (node) => {
    let found = false;
    const scan = (child) => {
      if (
        ts.isPrefixUnaryExpression(child)
        && child.operator === ts.SyntaxKind.ExclamationToken
        && ts.isIdentifier(child.operand)
        && child.operand.text === 'lastMutationTool'
      ) {
        found = true;
      }
      ts.forEachChild(child, scan);
    };
    scan(node);
    return found;
  };
  const visit = (node) => {
    if (ts.isIfStatement(node) && containsDirectDelivery(node.thenStatement)) {
      guarded = conditionRejectsMutation(node.expression);
    }
    ts.forEachChild(node, visit);
  };
  visit(handler);
  return guarded;
}

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

  const renderTools = new Map([
    ['preview_file', 'ui://desktop-commander/file-preview/v2'],
    ['render_directory', 'ui://desktop-commander/file-preview/v2'],
    ['render_config_editor', 'ui://desktop-commander/config-editor/v2'],
  ]);

  for (const [name, resourceUri] of renderTools) {
    const tool = byName.get(name);
    assert.ok(tool, `missing explicit render tool: ${name}`);
    assert.equal(tool._meta?.['ui/resourceUri'], resourceUri);
    assert.equal(tool._meta?.['openai/outputTemplate'], resourceUri);
    assert.equal(tool._meta?.ui?.resourceUri, resourceUri);
  }

  for (const tool of tools) {
    if (renderTools.has(tool.name)) {
      continue;
    }
    assert.equal(tool._meta?.['ui/resourceUri'], undefined, `${tool.name} must not mount UI`);
    assert.equal(tool._meta?.['openai/outputTemplate'], undefined, `${tool.name} must not mount UI`);
    assert.equal(tool._meta?.ui?.resourceUri, undefined, `${tool.name} must not mount UI`);
    assert.equal(
      tool._meta?.['openai/widgetAccessible'],
      undefined,
      `${tool.name} must not use legacy widgetAccessible metadata`,
    );
  }

  const preview = await client.callTool({
    name: 'preview_file',
    arguments: { path: previewImage },
  });
  assert.ok(!preview.isError, 'preview_file should read the selected file');
  assert.ok(preview.content?.some((item) => item.type === 'image'), 'preview_file must preserve model image content');
  assert.equal(preview.structuredContent?.fileType, 'image');
  assert.equal(preview.structuredContent?.filePath, previewImage);

  const directory = await client.callTool({
    name: 'render_directory',
    arguments: { path: isolatedHome, depth: 1 },
  });
  assert.ok(!directory.isError, 'render_directory should list the selected directory');
  assert.match(directory.content?.[0]?.text ?? '', /pixel\.png/);
  assert.equal(directory.structuredContent?.fileType, 'directory');
  assert.equal(directory.structuredContent?.filePath, isolatedHome);

  const configEditor = await client.callTool({ name: 'render_config_editor', arguments: {} });
  assert.ok(configEditor.structuredContent?.config, 'render_config_editor should provide config state');

  const staleBridgeArtifact = path.resolve(
    testDirectory,
    '..',
    'dist',
    'ui',
    'shared',
    'tool-bridge.js',
  );
  await assert.rejects(
    fs.access(staleBridgeArtifact),
    /ENOENT/,
    'clean builds must not retain the removed custom tool bridge in dist',
  );

  const previewSource = await fs.readFile(
    path.resolve(testDirectory, '..', 'src', 'ui', 'file-preview', 'src', 'app.ts'),
    'utf8',
  );
  const inputCalls = getAssignedHandlerCalls(previewSource, 'ontoolinput');
  const resultCalls = getAssignedHandlerCalls(previewSource, 'ontoolresult');
  assert.ok(!inputCalls.includes('pullPayloadByArgs'), 'ontoolinput must never eager-pull file content');
  assert.ok(resultCalls.includes('extractRenderPayload'), 'ontoolresult must hydrate from the correlated MCP Apps result');
  assert.ok(
    directPayloadDeliveryRejectsMutations(previewSource),
    'direct tool-result hydration must reject write_file/edit_block mutation results',
  );

  const configEditorBundle = await fs.readFile(
    path.resolve(testDirectory, '..', 'dist', 'ui', 'config-editor', 'config-editor-runtime.js'),
    'utf8',
  );
  assert.match(configEditorBundle, /callServerTool/, 'config editor must use the MCP Apps SDK tool-call API');
  assert.doesNotMatch(configEditorBundle, /createToolBridge/, 'config editor must not bundle the removed custom bridge');
  assert.doesNotMatch(
    configEditorBundle,
    /JSON-RPC fallback is unavailable in this host environment/,
    'config editor must not bundle the removed custom transport fallback',
  );

  console.log('UI render boundary contract: PASS');
} finally {
  await client.close();
  await fs.rm(isolatedHome, { recursive: true, force: true });
}
