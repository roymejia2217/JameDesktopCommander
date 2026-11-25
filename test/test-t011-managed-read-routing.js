import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import * as runtime from '../dist/server.js';
import { toolHistory } from '../dist/utils/toolHistory.js';

// Exercise the actual JDC MCP dispatcher. The injected operation is a
// transport-boundary test double, not a proof of OS broker authentication.
test('managed JDC routes read_file only to the enrolled operation, without persisting protected bytes', async () => {
  const marker = 'JDC_MANAGED_READ_CONTENT_NOT_FOR_HISTORY';
  const approved = '/managed/inside.txt';
  const calls = [];
  const server = runtime.createJdcServer({
    managedRead: async (request) => {
      calls.push(request);
      if (request.path !== approved) return { status: 'denied' };
      return { status: 'read', text: marker };
    },
  });
  const sdk = new Client({ name: 'desktop-commander-app', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await sdk.connect(clientTransport);
    const catalog = await sdk.listTools();
    assert.ok(catalog.tools.some(t => t.name === 'read_file'));
    const positive = await sdk.callTool({ name: 'read_file', arguments: { path: approved } });
    assert.notEqual(positive.isError, true, JSON.stringify(positive));
    assert.equal(positive.content[0].text, marker);
    assert.deepEqual(calls, [{ path: approved, offset: 0, length: 1000 }]);
    const recorded = toolHistory.getRecentCalls({ maxResults: 1 })[0];
    assert.equal(recorded.toolName, 'read_file');
    assert.equal(recorded.output.isError, false);
    assert.ok(!JSON.stringify(recorded).includes(marker));
    assert.ok(!JSON.stringify(recorded).includes(approved));

    const outside = await sdk.callTool({
      name: 'read_file', arguments: { path: '/outside.txt' },
      _meta: { 'jdc.nativeAuthorityRequired': false },
    });
    assert.equal(outside.isError, true);
    assert.match(outside.content[0].text, /E_NATIVE_READ_DENIED/);
    assert.ok(!JSON.stringify(outside).includes(marker));

    for (const [name, args] of [
      ['read_file', { path: approved, isUrl: true }],
      ['read_file', { path: approved, origin: 'ui' }],
      ['read_file', { path: approved, length: -1 }],
      ['read_file', { path: approved, rootRef: 'caller-selected' }],
      ['write_file', { path: approved, content: 'forbidden' }],
      ['start_process', { command: 'echo forbidden' }],
      ['get_recent_tool_calls', {}],
    ]) {
      const result = await sdk.callTool({ name, arguments: args });
      assert.equal(result.isError, true, name);
      assert.ok(!JSON.stringify(result).includes(marker), name);
    }
    assert.equal(calls.length, 2, 'unsupported calls must not reach the backend or legacy handlers');
  } finally {
    await sdk.close();
    await server.close();
  }
});
