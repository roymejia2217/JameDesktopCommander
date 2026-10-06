import assert from 'node:assert/strict';
import { once } from 'node:events';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { z } from 'zod/v4';
import { handleOpenCodeTask } from '../dist/tools/opencode.js';

const calls = [];
let waitMode = 'complete';
let waitEnteredResolve;

function result(payload) {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}

function createFakeGateway() {
  const server = new McpServer({ name: 'opencode-event-test', version: '1.0.0' });
  server.registerTool(
    'task_start',
    { inputSchema: { project: z.string(), prompt: z.string() } },
    async (args) => {
      calls.push({ name: 'task_start', args });
      return result({ project: args.project, sessionId: 'session-1' });
    },
  );
  server.registerTool(
    'task_wait',
    {
      inputSchema: {
        project: z.string(),
        sessionId: z.string(),
      },
    },
    async (args, extra) => {
      calls.push({ name: 'task_wait', args });
      if (waitMode === 'abort') {
        waitEnteredResolve?.();
        await new Promise((resolve, reject) => {
          if (extra.signal.aborted) {
            reject(extra.signal.reason);
            return;
          }
          extra.signal.addEventListener(
            'abort',
            () => reject(extra.signal.reason),
            { once: true },
          );
        });
      }
      return result({
        project: args.project,
        sessionId: args.sessionId,
        result: { state: 'completed', messageCount: 1 },
      });
    },
  );
  server.registerTool(
    'task_messages',
    {
      inputSchema: {
        project: z.string(),
        sessionId: z.string(),
      },
    },
    async (args) => {
      calls.push({ name: 'task_messages', args });
      return result({
        project: args.project,
        sessionId: args.sessionId,
        result: {
          messages: [{
            role: 'assistant',
            completed: true,
            failed: false,
            aborted: false,
            text: 'done',
          }],
        },
      });
    },
  );
  return server;
}

const app = createMcpExpressApp();
app.post('/rdc-mcp', async (req, res) => {
  const server = createFakeGateway();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } finally {
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
  }
});

const httpServer = app.listen(0, '127.0.0.1');
await once(httpServer, 'listening');
const address = httpServer.address();
assert.ok(address && typeof address === 'object');

const previousUrl = process.env.OPENCODE_GATEWAY_RDC_URL;
const previousToken = process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
try {
  process.env.OPENCODE_GATEWAY_RDC_URL =
    `http://127.0.0.1:${address.port}/rdc-mcp`;
  process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = 'A'.repeat(43);

  const response = await handleOpenCodeTask(
    {
      action: 'run',
      project: 'jamefirewall',
      prompt: 'implement safely',
      timeout_ms: 5000,
    },
    { signal: new AbortController().signal },
  );

  assert.equal(response.isError, undefined);
  assert.deepEqual(
    calls.map((entry) => entry.name),
    ['task_start', 'task_wait', 'task_messages'],
  );
  assert.equal(response.structuredContent?.state, 'completed');
  assert.equal(response.structuredContent?.latestAssistant?.text, 'done');

  waitMode = 'abort';
  calls.length = 0;
  const controller = new AbortController();
  const waitEntered = new Promise((resolve) => {
    waitEnteredResolve = resolve;
  });
  const pending = handleOpenCodeTask(
    {
      action: 'run',
      project: 'jamefirewall',
      prompt: 'cancel safely',
      timeout_ms: 5000,
    },
    { signal: controller.signal },
  );
  await waitEntered;
  controller.abort(new Error('cancelled by outer request'));
  await assert.rejects(pending);
  assert.deepEqual(
    calls.map((entry) => entry.name),
    ['task_start', 'task_wait'],
  );
} finally {
  if (previousUrl === undefined) delete process.env.OPENCODE_GATEWAY_RDC_URL;
  else process.env.OPENCODE_GATEWAY_RDC_URL = previousUrl;
  if (previousToken === undefined) delete process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN;
  else process.env.OPENCODE_GATEWAY_RDC_BRIDGE_TOKEN = previousToken;
  httpServer.close();
  await once(httpServer, 'close');
}

console.log('OpenCode event-driven gateway contract passed.');
