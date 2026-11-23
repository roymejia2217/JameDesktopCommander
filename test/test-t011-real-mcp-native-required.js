import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { server } from '../dist/server.js';
import { configManager } from '../dist/config-manager.js';

// Actual JDC src/server.ts tools/call and real read_file handler.
// NON-AUTHORIZING legacy baseline, not proof of a protected broker.
test('official SDK reaches actual JDC read_file and native-only calls deny with no fallback', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'jdc-real-mcp-'));
  const fixture = path.join(root, 'inside.txt');
  const original = 'JDC_REAL_HANDLER_BASELINE_EXACT\n';
  await writeFile(fixture, original);
  const saved = await configManager.getConfig();
  const previousRoots = [...(saved.allowedDirectories ?? [])];
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const sdk = new Client({ name: 'desktop-commander-app', version: '1.0.0' });
  try {
    await configManager.setValue('allowedDirectories', [root]);
    await server.connect(serverTransport);
    await sdk.connect(clientTransport);
    const catalog = await sdk.listTools();
    assert.ok(catalog.tools.some(tool => tool.name === 'read_file'),
      'This must be the real JDC server, not a fabricated MCP test server');

    const legacy = await sdk.callTool({ name: 'read_file', arguments: { path: fixture } });
    assert.notEqual(legacy.isError, true);
    assert.ok(legacy.content.some(item => item.type === 'text' && item.text.includes(original.trim())),
      'Legacy JDC read_file still works for already-authorized local files');

    // Client can demand stricter handling, never claim an authorization.
    // Without the protected SCM authority, a native-only call must not
    // silently reuse validatePath followed by pathname I/O.
    for (const nativeRequirement of [true, false, 'incorrect']) {
      const strictMeta = { 'jdc.nativeAuthorityRequired': nativeRequirement };
      for (const [name, args] of [
        ['read_file', { path: fixture }],
        ['preview_file', { path: fixture }],
        ['render_workspace', { path: fixture }],
        ['read_multiple_files', { paths: [fixture] }],
      ]) {
        const result = await sdk.callTool({ name, arguments: args, _meta: strictMeta });
        assert.equal(result.isError, true, name + ' must deny without a native broker');
        assert.ok(result.content.some(item => item.type === 'text' &&
          item.text.includes('E_NATIVE_AUTHORITY_UNAVAILABLE')),
        name + ' should report the exact fail-closed reason');
        assert.ok(!JSON.stringify(result).includes(original),
          name + ' must not fall back to ambient pathname I/O');
      }
    }
  } finally {
    await sdk.close();
    await server.close();
    await configManager.setValue('allowedDirectories', previousRoots);
    await rm(root, { recursive: true, force: true });
  }
});
