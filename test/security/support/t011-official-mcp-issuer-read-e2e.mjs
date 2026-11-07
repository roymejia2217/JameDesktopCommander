// Disposable Linux CI-only acceptance: official MCP SDK over stdio ->
// kernel-authenticated Rust issuer over AF_UNIX -> retained directory handles.
// This module is NOT a production MCP server or an authorization source.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { z } from 'zod';
import { createIssuerReadClient, AuthorityReadTransportError } from './authority-read-client.mjs';
import * as frameContract from '../../../dist/security/authority-frame-contract.js';
import * as operationContract from '../../../dist/security/authority-operation-contract.js';

if (process.platform !== 'linux' || process.getuid?.() === 0 ||
    process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_OS !== 'Linux' ||
    process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw Error('E_T011_DISPOSABLE_LINUX_RUNNER_REQUIRED');
}

const root = '0123456789abcdef0123456789abcdef';
const secondRoot = 'fedcba9876543210fedcba9876543210';
const client = createIssuerReadClient({ ...frameContract, ...operationContract });
const fields = {
  requestId: z.string(), expectedEpoch: z.string(),
  rootRef: z.string(), relativePath: z.string(),
};
const response = (text, isError = false) => ({
  content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}),
});
async function runServer() {
  const server = new McpServer({ name: 'jdc-t011-native-e2e-nonrelease', version: '1.0.0' });
  server.registerTool('read_file', { inputSchema: fields }, async args => {
    try {
      const reply = await client.requestIssuerOwnedRead({ version: 1, kind: 'read-file', ...args });
      return reply.status === 'ok'
        ? response(reply.bytes.toString('base64')) : response('E_AUTHORITY_DENIED', true);
    } catch (error) {
      const code = error instanceof AuthorityReadTransportError &&
        error.code === 'E_AUTHORITY_REQUEST_INVALID'
        ? 'E_AUTHORITY_REQUEST_INVALID' : 'E_AUTHORITY_UNAVAILABLE';
      return response(code, true);
    }
  });
  server.registerTool('list_directory', { inputSchema: fields }, async args => {
    try {
      const reply = await client.requestIssuerOwnedList({ version: 1, kind: 'list-directory', ...args });
      return reply.status === 'ok'
        ? response(JSON.stringify(reply.entries)) : response('E_AUTHORITY_DENIED', true);
    } catch (error) {
      const code = error instanceof AuthorityReadTransportError &&
        error.code === 'E_AUTHORITY_REQUEST_INVALID'
        ? 'E_AUTHORITY_REQUEST_INVALID' : 'E_AUTHORITY_UNAVAILABLE';
      return response(code, true);
    }
  });
  await server.connect(new StdioServerTransport());
}

function checkedText(result) {
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.equal(result.content.length, 1, 'one bounded tool content block');
  assert.equal(result.content[0].type, 'text');
  return result.content[0].text;
}
async function runClient() {
  const sdkClient = new Client({ name: 'jdc-t011-official-sdk-native-e2e', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(import.meta.url), 'server'],
    cwd: process.cwd(), stderr: 'inherit',
    // No GitHub secrets, authentication tokens or unreviewed environment
    // forwarded to the disposable server subprocess.
    env: {
      PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '',
      GITHUB_ACTIONS: 'true', RUNNER_OS: 'Linux', RUNNER_ENVIRONMENT: 'github-hosted',
    },
  });
  try {
    await sdkClient.connect(transport);
    const available = await sdkClient.listTools();
    assert.deepEqual(available.tools.map(tool => tool.name).sort(),
      ['list_directory', 'read_file']);
    const common = { expectedEpoch: '1', rootRef: root };
    const invalid = await sdkClient.callTool({ name: 'read_file', arguments: {
      ...common, relativePath: 'inside.bin', requestId: 'not-a-uuid',
    } });
    assert.equal(invalid.isError, true, 'invalid frame must not reach Rust');
    assert.equal(invalid.content[0]?.text, 'E_AUTHORITY_REQUEST_INVALID');
    const first = await sdkClient.callTool({ name: 'read_file', arguments: {
      ...common, relativePath: 'inside.bin',
      requestId: '11111111-1111-4111-8111-111111111111',
    } });
    assert.deepEqual(Buffer.from(checkedText(first), 'base64'),
      Buffer.from([0, 255, 0x81, 42, 74, 68, 67, 10]));
    console.log('T011_OFFICIAL_MCP_SDK_NATIVE_READ_EXACT_BYTES_PASS');
    const second = await sdkClient.callTool({ name: 'read_file', arguments: {
      ...common, rootRef: secondRoot, relativePath: 'inside2.bin',
      requestId: '22222222-2222-4222-8222-222222222222',
    } });
    assert.deepEqual(Buffer.from(checkedText(second), 'base64'),
      Buffer.concat([Buffer.from([2, 0, 0x43, 0x2a]), Buffer.from('SECOND\n')]));
    console.log('T011_OFFICIAL_MCP_SDK_NATIVE_SECOND_ROOT_READ_PASS');
    const listing = await sdkClient.callTool({ name: 'list_directory', arguments: {
      ...common, relativePath: 'nested',
      requestId: '33333333-3333-4333-8333-333333333333',
    } });
    assert.deepEqual(JSON.parse(checkedText(listing)), ['a.txt', 'z.txt']);
    console.log('T011_OFFICIAL_MCP_SDK_NATIVE_LIST_PASS');
  } finally {
    await sdkClient.close();
  }
}

if (process.argv[2] === 'server') await runServer();
else if (process.argv[2] === 'client') await runClient();
else throw Error('E_T011_MCP_PROBE_MODE_REQUIRED');