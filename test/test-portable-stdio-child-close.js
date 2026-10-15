import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

async function within(label, promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' deadline exceeded')), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test('MCP child closes before cleanup of an isolated Windows-capable workspace',
  { timeout: 40000 }, async () => {
    const isolated = await mkdtemp(join(tmpdir(), 'jdc-stdio-close-'));
    const env = {
      ...process.env, HOME: isolated, USERPROFILE: isolated,
      APPDATA: join(isolated, 'appdata'),
      LOCALAPPDATA: join(isolated, 'localappdata'),
      DESKTOP_COMMANDER_CONFIG_DIR: join(isolated, 'config'),
      DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
      PUPPETEER_SKIP_DOWNLOAD: '1',
    };
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [join(process.cwd(), 'dist/index.js'), '--no-onboarding'],
      cwd: isolated, env, stderr: 'ignore',
    });
    const client = new Client(
      { name: 'jdc-child-close-contract', version: '1.0.0' },
      { capabilities: {} },
    );
    let signalClosed;
    const childClosed = new Promise((resolve) => { signalClosed = resolve; });
    client.onclose = () => signalClosed();
    let childStarted = false;
    try {
      await within('MCP initialize', client.connect(transport), 18000);
      childStarted = transport.pid !== null;
      const { tools } = await within('MCP tool discovery', client.listTools(), 10000);
      assert.ok(tools.some((tool) => tool.name === 'get_config'));
    } finally {
      const mustWait = childStarted || transport.pid !== null;
      await client.close().catch(() => {});
      if (mustWait) await within('MCP child exit', childClosed, 12000);
      await rm(isolated, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
