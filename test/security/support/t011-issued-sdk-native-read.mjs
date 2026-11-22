// Non-shipping SDK/native integration. Identity is attested by the Rust
// kernel-peer fixture, never by this JavaScript module or its MCP input.
import { connect } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const LIMIT = 1024 * 1024;
async function readAttestedNative(socketPath) {
  const channel = connect(socketPath);
  channel.setTimeout(3000, () => channel.destroy(new Error('E_NATIVE_TIMEOUT')));
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
export async function exerciseIssuedSdkRead(socketPath) {
  const server = new McpServer({ name: 'jdc-t011-issued-peer-nonrelease', version: '1.0.0' });
  server.registerTool('read_file', { inputSchema: {} }, async () => {
    try {
      const bytes = await readAttestedNative(socketPath);
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

if (process.argv[1]?.endsWith('t011-issued-sdk-native-read.mjs') && process.argv.length === 3) {
  if (process.platform !== 'linux' || process.getuid?.() === 0 ||
      process.env.GITHUB_ACTIONS !== 'true' ||
      process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    throw Error('E_T011_DISPOSABLE_LINUX_ONLY');
  }
  const bytes = await exerciseIssuedSdkRead(process.argv[2]);
  if (!bytes.equals(Buffer.from('SERVICE_DOMAIN_BYTES'))) {
    throw Error('E_T011_SDK_NATIVE_BYTES_MISMATCH');
  }
  console.error('T011_LINUX_ROOT_ISSUED_OFFICIAL_SDK_NATIVE_BYTES_PASS_NONRELEASE');
}
