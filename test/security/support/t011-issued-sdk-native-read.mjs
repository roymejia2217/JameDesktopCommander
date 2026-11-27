// Non-shipping SDK/native integration. Identity is attested by the Rust
// kernel-peer fixture, never by this JavaScript module or its MCP input.
import { connect } from 'node:net';
import { readSync, writeSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const LIMIT = 1024 * 1024;
async function readAttestedNative(socketPath, timeoutMs, signal) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 10000) {
    throw Error('E_NATIVE_INVALID_TIMEOUT');
  }
  const deadline = AbortSignal.timeout(timeoutMs);
  const bounded = signal ? AbortSignal.any([signal, deadline]) : deadline;
  bounded.throwIfAborted();
  const channel = connect({ path: socketPath, signal: bounded });
  let frame = Buffer.alloc(0);
  let stage = 'challenge';
  let expected = null;
  try {
    for await (const chunk of channel) {
      frame = Buffer.concat([frame, chunk]);
      if (frame.length > LIMIT + 6) throw Error('E_NATIVE_READ_DENIED');
      if (stage === 'challenge' && frame.length > 0) {
        if (frame[0] !== 0x43) throw Error('E_NATIVE_READ_DENIED');
        frame = frame.subarray(1);
        stage = 'header';
        channel.write('R');
      }
      if (stage === 'header' && frame.length >= 5) {
        if (frame[0] !== 0x41) throw Error('E_NATIVE_READ_DENIED');
        expected = frame.readUInt32BE(1);
        if (expected > LIMIT) throw Error('E_NATIVE_READ_DENIED');
        frame = frame.subarray(5);
        stage = 'payload';
      }
    }
    if (stage !== 'payload' || expected === null || frame.length !== expected) {
      throw Error('E_NATIVE_READ_DENIED');
    }
    return frame;
  } finally {
    channel.destroy();
  }
}

// Real official MCP Client.callTool -> McpServer.registerTool -> native IPC.
export async function exerciseIssuedSdkRead(socketPath, timeoutMs = 3000) {
  const server = new McpServer({ name: 'jdc-t011-issued-peer-nonrelease', version: '1.0.0' });
  server.registerTool('read_file', { inputSchema: {} }, async () => {
    try {
      const bytes = await readAttestedNative(socketPath, timeoutMs);
      return { content: [{ type: 'text', text: bytes.toString('base64') }] };
    } catch {
      return { isError: true, content: [{ type: 'text', text: 'E_NATIVE_READ_DENIED' }] };
    }
  });
  const sdk = new Client({ name: 'jdc-t011-official-sdk', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await sdk.connect(clientTransport);
    const catalog = await sdk.listTools();
    if (catalog.tools.length !== 1 || catalog.tools[0].name !== 'read_file') {
      throw Error('E_MCP_TOOL_SURFACE');
    }
    const reply = await sdk.callTool({ name: 'read_file', arguments: {} });
    if (reply.isError || reply.content?.length !== 1 ||
        reply.content[0]?.type !== 'text') throw Error('E_NATIVE_READ_DENIED');
    return Buffer.from(reply.content[0].text, 'base64');
  } finally {
    await sdk.close();
    await server.close();
  }
}

// The hosted positive path uses the actual JDC server, not the SDK-only
// server above. This disposable adapter binds the sole fixture object; it
// does not establish a general-purpose policy or a shipping broker.
export async function exerciseIssuedJdcRead(socketPath, createJdcServer, timeoutMs = 3000) {
  const approved = '/managed/service.bin';
  let operations = 0;
  const server = createJdcServer({
    managedRead: async (request, signal) => {
      if (request.path !== approved) return { status: 'denied' };
      if (request.offset !== 0 || request.length !== 1000) return { status: 'unsupported' };
      operations++;
      try {
        const bytes = await readAttestedNative(socketPath, timeoutMs, signal);
        // The fixture compares exact native bytes after the MCP round trip.
        // Preserve an initial BOM as U+FEFF rather than silently stripping it.
        return { status: 'read', text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) };
      } catch {
        return { status: 'denied' };
      }
    },
  });
  const sdk = new Client({ name: 'desktop-commander-app', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await sdk.connect(clientTransport);
    const catalog = await sdk.listTools();
    if (!catalog.tools.some(tool => tool.name === 'read_file') ||
        !catalog.tools.some(tool => tool.name === 'start_process')) throw Error('E_REAL_JDC_CATALOG');
    for (const [name, args] of [
      ['read_file', { path: '/outside.bin' }],
      ['read_file', { path: approved, length: 1 }],
      ['start_process', { command: 'echo forbidden' }],
      ['write_file', { path: approved, content: 'forbidden' }],
    ]) {
      const denial = await sdk.callTool({ name, arguments: args,
        _meta: { 'jdc.nativeAuthorityRequired': false } });
      if (!denial.isError) throw Error('E_REAL_JDC_EXPECTED_DENIAL');
    }
    if (operations !== 0) throw Error('E_REAL_JDC_UNEXPECTED_NATIVE_OPERATION');
    const reply = await sdk.callTool({ name: 'read_file', arguments: { path: approved } });
    if (reply.isError || reply.content?.length !== 1 ||
        reply.content[0]?.type !== 'text' || operations !== 1) {
      throw Error('E_REAL_JDC_NATIVE_READ_DENIED');
    }
    return Buffer.from(reply.content[0].text, 'utf8');
  } finally {
    await sdk.close();
    await server.close();
  }
}

if (process.argv[1]?.endsWith('t011-issued-sdk-native-read.mjs') && process.argv.length === 3) {
  if (process.platform !== 'linux' || process.getuid?.() === 0 ||
      process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    throw Error('E_T011_DISPOSABLE_LINUX_ONLY');
  }
  // The root issuer owns the other end of this anonymous readiness socket.
  // No broker request is made before post-exec kernel custody is verified.
  const release = Buffer.alloc(1);
  if (writeSync(0, 'R') !== 1 || readSync(0, release, 0, 1, null) !== 1 || release[0] !== 0x41) {
    throw Error('E_T011_SDK_STARTUP_PROTOCOL');
  }
  const home = fileURLToPath(new URL('./client-state/', import.meta.url));
  process.env.HOME = home;
  process.env.DESKTOP_COMMANDER_CONFIG_DIR = home;
  process.env.DESKTOP_COMMANDER_DISABLE_TELEMETRY = '1';
  process.env.DC_FLAG_URL = 'http://127.0.0.1:9/';
  const { createJdcServer } = await import('./dist/server.js');
  const bytes = await exerciseIssuedJdcRead(process.argv[2], createJdcServer);
  if (!bytes.equals(Buffer.from('SERVICE_DOMAIN_BYTES'))) {
    throw Error('E_T011_SDK_NATIVE_BYTES_MISMATCH');
  }
  console.error('T011_LINUX_ROOT_ISSUED_REAL_JDC_MANAGED_READ_PASS_NONRELEASE');
  console.error('T011_LINUX_ROOT_ISSUED_OFFICIAL_SDK_NATIVE_BYTES_PASS_NONRELEASE');
}
