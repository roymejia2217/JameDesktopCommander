import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { test } from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { z } from 'zod/v4';
import { handleOpenCodeRead, handleOpenCodeTask } from '../../dist/tools/opencode.js';

const contract = JSON.parse(readFileSync(new URL('../../contracts/opencode-gateway.json', import.meta.url), 'utf8'));
const examples = JSON.parse(readFileSync(new URL('../../contracts/opencode-gateway-examples.json', import.meta.url), 'utf8'));

test('public synthetic examples exactly cover the reviewed MCP surface', () => {
  assert.equal(examples.formatVersion, 1);
  assert.deepEqual(Object.keys(examples.cases).sort(), contract.requiredTools);
  assert.equal(examples.errorExamples.length, 2);
  for (const [name, pair] of Object.entries(examples.cases)) {
    assert.ok(pair.request && typeof pair.request === 'object' && !Array.isArray(pair.request), name + ' request must be an object');
    assert.ok(pair.response && typeof pair.response === 'object' && !Array.isArray(pair.response), name + ' response must be an object');
    assert.ok(!JSON.stringify(pair).includes('workingDirectory'));
  }
  assert.doesNotMatch(JSON.stringify(examples), /(?:[A-Z]:[\\/]|\\\\\\\\)/i);
});

test('actual JDC client accepts public synthetic MCP success and error envelopes', async () => {
  let failure = null;
  const app = createMcpExpressApp();
  app.post('/rdc-mcp', async (req, res) => {
    const server = new McpServer({ name: 'public-synthetic-contract', version: '1.0.0' });
    for (const [name, pair] of Object.entries(examples.cases)) {
      const inputSchema = Object.fromEntries(
        Object.keys(pair.request).map((key) => [key, z.string()]),
      );
      server.registerTool(name, { inputSchema }, async () => {
        if (name === 'task_status' && failure) {
          const value = { error: failure };
          return {
            isError: true,
            structuredContent: value,
            content: [{ type: 'text', text: JSON.stringify(value) }],
          };
        }
        return {
          structuredContent: pair.response,
          content: [{ type: 'text', text: JSON.stringify(pair.response) }],
        };
      });
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => { void transport.close(); void server.close(); });
  });
  const listener = app.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const address = listener.address();
  assert.ok(address && typeof address === 'object');
  const previousUrl = process.env.OPENCODE_GATEWAY_RDC_URL;
  const previousToken = process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
  process.env.OPENCODE_GATEWAY_RDC_URL = 'http://127.0.0.1:' + address.port + '/rdc-mcp';
  process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = 'A'.repeat(43);
  const project = examples.cases.task_status.request.project;
  const sessionId = examples.cases.task_status.request.sessionId;
  try {
    for (const action of ['health', 'projects', 'sessions', 'status', 'messages', 'diff']) {
      const result = await handleOpenCodeRead({ action, project, sessionId });
      assert.equal(result.isError, undefined, 'read ' + action);
      const matchingTool = {
        health: 'gateway_health', projects: 'project_list', sessions: 'task_sessions',
        status: 'task_status', messages: 'task_messages', diff: 'task_diff',
      }[action];
      assert.deepEqual(result.structuredContent, examples.cases[matchingTool].response);
    }
    for (const action of ['start', 'run', 'continue', 'abort']) {
      const result = await handleOpenCodeTask({
        action, project, sessionId, prompt: 'synthetic test request', timeout_ms: 10000,
      });
      assert.equal(result.isError, undefined, 'task ' + action);
      assert.equal(result.structuredContent?.project, project);
      assert.equal(result.structuredContent?.sessionId, sessionId);
    }
    for (const error of examples.errorExamples) {
      failure = error;
      await assert.rejects(
        () => handleOpenCodeRead({ action: 'status', project, sessionId }),
        new RegExp('OpenCode gateway ' + error.code + ': ' + error.message),
      );
    }
  } finally {
    if (previousUrl === undefined) delete process.env.OPENCODE_GATEWAY_RDC_URL;
    else process.env.OPENCODE_GATEWAY_RDC_URL = previousUrl;
    if (previousToken === undefined) delete process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
    else process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = previousToken;
    listener.close();
    await once(listener, 'close');
  }
});
