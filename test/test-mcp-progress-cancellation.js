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
const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), 'jdc-progress-'));
const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/sh';

function shellQuote(value) {
  return process.platform === 'win32'
    ? `'${value.replaceAll("'", "''")}'`
    : `'${value.replaceAll("'", "'\"'\"'")}'`;
}

async function writeNodeFixture(name, source) {
  const scriptPath = path.join(isolatedHome, `${name}.cjs`);
  await fs.writeFile(scriptPath, source, 'utf8');
  return scriptPath;
}

function nodeCommand(scriptPath, args = []) {
  const parts = [process.execPath, scriptPath, ...args].map(shellQuote);
  return process.platform === 'win32' ? `& ${parts.join(' ')}` : parts.join(' ');
}

function textOf(result) {
  return result.content?.filter((item) => item.type === 'text').map((item) => item.text).join('\n') ?? '';
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForFile(filePath, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await sleep(25);
    }
  }
  throw new Error(`Timed out waiting for ${filePath}`);
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    throw error;
  }
}

const client = new Client(
  { name: 'jdc-progress-contract', version: '1.0.0' },
  { capabilities: {} },
);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint],
  env: { ...process.env, HOME: isolatedHome, USERPROFILE: isolatedHome },
});

async function listActivePids() {
  const result = await client.callTool({ name: 'list_sessions', arguments: {} });
  const text = textOf(result);
  return {
    text,
    pids: [...text.matchAll(/PID:\s*(-?\d+)/g)].map((match) => Number(match[1])),
  };
}

async function cleanupActiveSessions() {
  const { pids } = await listActivePids();
  for (const pid of pids) {
    await client.callTool({ name: 'force_terminate', arguments: { pid } });
  }
}

await client.connect(transport);

try {
  const progress = [];
  const progressResult = await client.callTool(
    {
      name: 'start_process',
      arguments: {
        command: nodeCommand(
          await writeNodeFixture(
            'progress',
            "let i=0;const t=setInterval(()=>{console.log(++i);if(i===3)clearInterval(t)},100)",
          ),
        ),
        timeout_ms: 5000,
        shell,
      },
    },
    undefined,
    {
      timeout: 10000,
      resetTimeoutOnProgress: true,
      onprogress: (notification) => progress.push(notification),
    },
  );

  assert.equal(progressResult.isError, undefined, textOf(progressResult));
  assert.ok(progress.length >= 2, 'start_process must emit multiple progress notifications');
  for (let index = 1; index < progress.length; index++) {
    assert.ok(
      progress[index].progress >= progress[index - 1].progress,
      'progress values must be monotonic',
    );
  }
  assert.ok(
    progress.some((notification) => /started|running|output/i.test(notification.message ?? '')),
    'progress must communicate a meaningful process phase',
  );
  assert.ok(progress.length <= 6, 'short processes must not spam progress notifications');

  const fallbackResult = await client.callTool({
    name: 'start_process',
    arguments: {
      command: nodeCommand(
        await writeNodeFixture('fallback', "console.log('fallback-ok')"),
      ),
      timeout_ms: 5000,
      shell,
    },
  });
  assert.match(textOf(fallbackResult), /fallback-ok/);

  const childPidPath = path.join(isolatedHome, 'cancel-child.pid');
  const controller = new AbortController();
  const cancelledCall = client.callTool(
    {
      name: 'start_process',
      arguments: {
        command: nodeCommand(
          await writeNodeFixture(
            'cancel-child',
            "require('node:fs').writeFileSync(process.argv[2], String(process.pid));setInterval(()=>{},1000)",
          ),
          [childPidPath],
        ),
        timeout_ms: 30000,
        shell,
      },
    },
    undefined,
    { signal: controller.signal, timeout: 35000 },
  );

  const childPid = Number((await waitForFile(childPidPath)).trim());
  assert.ok(Number.isInteger(childPid) && childPid > 0, 'child PID marker must contain a real PID');
  controller.abort();
  await assert.rejects(cancelledCall);
  await sleep(1000);

  const activeAfterCancel = await listActivePids();
  assert.equal(
    activeAfterCancel.text,
    'No active sessions',
    'cancelling start_process must not leave an active process session',
  );
  assert.equal(
    processExists(childPid),
    false,
    'cancelling start_process must terminate the spawned child process tree',
  );

  const backgroundResult = await client.callTool({
    name: 'start_process',
    arguments: {
      command: nodeCommand(
        await writeNodeFixture('background', "setInterval(()=>{},1000)"),
      ),
      timeout_ms: 150,
      shell,
    },
  });
  const backgroundPidMatch = textOf(backgroundResult).match(/PID\s+(\d+)/);
  assert.ok(backgroundPidMatch, 'background process result must expose its PID');
  const backgroundPid = Number(backgroundPidMatch[1]);

  const readProgress = [];
  const readController = new AbortController();
  const readCall = client.callTool(
    {
      name: 'read_process_output',
      arguments: { pid: backgroundPid, timeout_ms: 30000, offset: 0, length: 20 },
    },
    undefined,
    {
      signal: readController.signal,
      timeout: 35000,
      onprogress: (notification) => readProgress.push(notification),
    },
  );
  setTimeout(() => readController.abort(), 300);
  await assert.rejects(readCall);
  await sleep(300);

  const activeAfterReadCancel = await listActivePids();
  assert.ok(
    activeAfterReadCancel.pids.includes(backgroundPid),
    'cancelling read_process_output must not terminate the underlying process',
  );
  assert.ok(
    readProgress.some((notification) => /waiting for output/i.test(notification.message ?? '')),
    'read_process_output must report that it is waiting for output',
  );
  await client.callTool({ name: 'force_terminate', arguments: { pid: backgroundPid } });

  console.log('MCP progress and cancellation contract: PASS');
} finally {
  await cleanupActiveSessions().catch(() => {});
  await client.close();
  await fs.rm(isolatedHome, { recursive: true, force: true });
}
