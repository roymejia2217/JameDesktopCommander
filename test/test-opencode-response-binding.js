import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { z } from 'zod/v4';
import { handleOpenCodeRead, handleOpenCodeTask } from '../dist/tools/opencode.js';

const expectedProject = 'test-project';
const expectedSession = 'ses_expected';
const foreignProject = 'foreign-project';
const foreignSession = 'ses_foreign';
const selectors = { project: expectedProject, sessionId: expectedSession };

function envelope(value) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

test('OpenCode adapter binds returned project and session to the requested selector', async () => {
  const reply = { project: expectedProject, sessionId: expectedSession, errorMode: null };
  const app = createMcpExpressApp();
  app.post('/rdc-mcp', async (req, res) => {
    const server = new McpServer({ name: 'synthetic-contract', version: '1.0.0' });
    const selector = { project: z.string(), sessionId: z.string() };
    const add = (name, inputSchema, produce) => server.registerTool(
      name,
      { inputSchema },
      async (args) => {
        if (name === 'task_status' && reply.errorMode) {
          const value = reply.errorMode === 'structured'
            ? { error: { code: 'PROJECT_DENIED', message: 'request rejected' } }
            : { error: 'malformed-envelope' };
          return { ...envelope(value), isError: true };
        }
        return envelope(produce(args));
      },
    );

    add('task_sessions', { project: z.string() }, () => ({
      project: reply.project, result: { sessions: [] },
    }));
    add('task_status', selector, () => ({
      ...reply, result: { state: 'completed', messageCount: 1 },
    }));
    add('task_diff', selector, () => ({ ...reply, result: [] }));
    add('task_messages', selector, () => ({
      ...reply, result: { messages: [{
        role: 'assistant', completed: true, failed: false, aborted: false, text: 'synthetic',
      }] },
    }));
    add('task_start', { project: z.string(), prompt: z.string() }, () => ({
      project: reply.project, sessionId: expectedSession,
    }));
    add('task_continue', {
      project: z.string(), sessionId: z.string(), prompt: z.string(),
    }, () => ({ accepted: true, ...reply }));
    add('task_wait', selector, () => ({
      ...reply, result: { state: 'completed', messageCount: 1 },
    }));
    add('task_abort', selector, () => ({ ...reply, aborted: true }));

    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
  });

  const listener = app.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const address = listener.address();
  assert.ok(address && typeof address === 'object');
  const previousUrl = process.env.OPENCODE_GATEWAY_RDC_URL;
  const previousToken = process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
  process.env.OPENCODE_GATEWAY_RDC_URL = `http://127.0.0.1:${address.port}/rdc-mcp`;
  process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = 'A'.repeat(43);

  try {
    const status = await handleOpenCodeRead({ action: 'status', ...selectors });
    assert.equal(status.structuredContent?.project, expectedProject);

    reply.errorMode = 'structured';
    await assert.rejects(
      () => handleOpenCodeRead({ action: 'status', ...selectors }),
      /OpenCode gateway PROJECT_DENIED: request rejected/,
    );
    reply.errorMode = 'malformed';
    await assert.rejects(
      () => handleOpenCodeRead({ action: 'status', ...selectors }),
      /OpenCode gateway returned an error/,
    );
    reply.errorMode = null;

    reply.project = foreignProject;
    for (const action of ['sessions', 'status', 'messages', 'diff']) {
      await assert.rejects(
        () => handleOpenCodeRead({ action, ...selectors }),
        /gateway response project mismatch/i,
        'Cross-project response must be rejected: ' + action,
      );
    }
    for (const action of ['start', 'run', 'continue', 'abort']) {
      const args = {
        action, ...selectors, prompt: 'synthetic prompt', timeout_ms: 5000,
      };
      await assert.rejects(
        () => handleOpenCodeTask(args),
        /gateway response project mismatch/i,
        'Cross-project task response must be rejected: ' + action,
      );
    }

    reply.project = expectedProject;
    reply.sessionId = foreignSession;
    for (const action of ['status', 'messages', 'diff']) {
      await assert.rejects(
        () => handleOpenCodeRead({ action, ...selectors }),
        /gateway response session mismatch/i,
        'Cross-session response must be rejected: ' + action,
      );
    }
    for (const action of ['run', 'continue', 'abort']) {
      const args = {
        action, ...selectors, prompt: 'synthetic prompt', timeout_ms: 5000,
      };
      await assert.rejects(
        () => handleOpenCodeTask(args),
        /gateway response session mismatch/i,
        'Cross-session task response must be rejected: ' + action,
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
