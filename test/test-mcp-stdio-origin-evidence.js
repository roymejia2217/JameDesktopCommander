// #139 non-shipping observation: MCP SDK stdio metadata is not OS issuer identity.
// This tests public tools/list only; it never requests privileged filesystem bytes.
import assert from 'node:assert/strict';
import { fork, execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';

const TEST = fileURLToPath(import.meta.url);
const ROOT = resolve(dirname(TEST), '..');
const SERVER = join(ROOT, 'dist', 'index.js');
const CHILD_MODE = 'JDC_T011_TEST_ORIGIN_WORKER';
const METADATA = { name: 'desktop-commander-app', version: '1.0.0' };

function principalFromOs() {
  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot;
    assert.ok(systemRoot, 'Windows SystemRoot is required for native SID evidence');
    // Use the Windows system utility, never a PATH-shadowing GNU whoami.
    const report = execFileSync(join(systemRoot, 'System32', 'whoami.exe'),
      ['/user', '/fo', 'csv', '/nh'],
      { encoding: 'utf8', windowsHide: true, timeout: 5_000 });
    const sid = report.match(/S-\d+(?:-\d+)+/u)?.[0];
    assert.ok(sid, 'Windows token SID must come from whoami, not an env var');
    return sid;
  }
  const uid = process.getuid?.();
  assert.ok(Number.isSafeInteger(uid), 'POSIX UID must come from the OS');
  return String(uid);
}

async function bounded(label, operation, limitMs) {
  let timeout;
  try {
    return await Promise.race([
      operation,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(label + ': bounded deadline exceeded')), limitMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

async function observedSdkConnection() {
  const isolated = await mkdtemp(join(tmpdir(), 'jdc-mcp-origin-'));
  const client = new Client(METADATA, { capabilities: {} });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER, '--no-onboarding'],
    cwd: isolated,
    env: {
      ...getDefaultEnvironment(),
      HOME: isolated,
      USERPROFILE: isolated,
      APPDATA: join(isolated, 'appdata'),
      LOCALAPPDATA: join(isolated, 'localappdata'),
      DESKTOP_COMMANDER_CONFIG_DIR: join(isolated, 'config'),
      DESKTOP_COMMANDER_DISABLE_TELEMETRY: '1',
      PUPPETEER_SKIP_DOWNLOAD: '1',
    },
    stderr: 'ignore',
  });
  let signalClose;
  const closed = new Promise((resolve) => { signalClose = resolve; });
  client.onclose = () => signalClose();
  let connected = false;
  try {
    await bounded('MCP SDK initialize', client.connect(transport), 20_000);
    connected = true;
    assert.ok(Number.isSafeInteger(transport.pid) && transport.pid > 0);
    const { tools } = await bounded('MCP SDK tools/list', client.listTools(), 12_000);
    assert.ok(tools.some(({ name }) => name === 'get_config'));
    assert.ok(tools.some(({ name }) => name === 'read_file'));
    return { launcherPid: process.pid, serverPid: transport.pid,
      principal: principalFromOs(), publicToolsListed: true };
  } finally {
    await client.close().catch(() => {});
    if (connected) await bounded('stdio server close', closed, 12_000);
    await rm(isolated, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

async function independentLauncher() {
  const child = fork(TEST, [], {
    execArgv: [],
    env: { ...process.env, [CHILD_MODE]: '1' },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  let diagnostics = '';
  child.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
  try {
    return await bounded('independent SDK launcher', new Promise((resolve, reject) => {
      child.once('message', message => {
        if (message.type === 'result') resolve(message.result);
        else reject(new Error('independent launcher failed: ' + message.error + '\n' + diagnostics));
      });
      child.once('error', reject);
      child.once('exit', code => {
        if (code !== 0) reject(new Error('independent launcher exited ' + code + '\n' + diagnostics));
      });
    }), 45_000);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}

if (process.env[CHILD_MODE] === '1') {
  try {
    process.send?.({ type: 'result', result: await observedSdkConnection() });
  } catch (error) {
    process.send?.({ type: 'error', error: String(error?.stack ?? error) });
    process.exitCode = 1;
  } finally {
    process.disconnect?.();
  }
} else {
  test('independent same-principal SDK launchers can claim identical client metadata',
    { timeout: 90_000 }, async () => {
      const original = await observedSdkConnection();
      const independent = await independentLauncher();
      assert.notEqual(original.launcherPid, independent.launcherPid);
      assert.notEqual(original.serverPid, original.launcherPid);
      assert.notEqual(independent.serverPid, independent.launcherPid);
      assert.ok(original.principal === independent.principal,
        'both independent launchers must have the same OS token principal');
      assert.equal(original.publicToolsListed, true);
      // Deliberately preserve the observed falsification: both distinct
      // launchers can announce identical client metadata to the SDK. Public
      // tool discovery is not a protected launcher or filesystem grant.
      assert.equal(independent.publicToolsListed, true,
        'a standard SDK handshake cannot attest the original host identity');
    });
}
