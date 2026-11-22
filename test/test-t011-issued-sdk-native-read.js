import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:net';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { unlink } from 'node:fs/promises';
import { exerciseIssuedSdkRead } from './security/support/t011-issued-sdk-native-read.mjs';

async function withNativeFixture(reply, evaluate) {
  const socketPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\jdc-issued-sdk-${randomUUID()}`
    : path.join(tmpdir(), `jdc-issued-sdk-${randomUUID()}.sock`);
  const server = createServer((connection) => {
    connection.write('C');
    connection.once('data', (request) => {
      assert.deepEqual(request, Buffer.from('R'));
      connection.end(reply);
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    await evaluate(socketPath);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (process.platform !== 'win32') await unlink(socketPath).catch(() => {});
  }
}
test('official MCP SDK tool returns exact native bytes over real OS stream', async () => {
  const bytes = Buffer.from([0, 255, 0x81, 0x2a, 0x4a, 0x44, 0x43, 10]);
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  await withNativeFixture(Buffer.concat([Buffer.from('A'), length, bytes]),
    async (socket) => {
      const output = await exerciseIssuedSdkRead(socket);
      assert.deepEqual(output, bytes);
    });
});

test('official MCP SDK tool rejects native denial without returning bytes', async () => {
  await withNativeFixture(Buffer.from('D'), async (socket) => {
    await assert.rejects(exerciseIssuedSdkRead(socket), /E_NATIVE_READ_DENIED/);
  });
});

test('official MCP SDK tool rejects malformed native lengths', async () => {
  const oversized = Buffer.allocUnsafe(5);
  oversized[0] = 0x41;
  oversized.writeUInt32BE(1024 * 1024 + 1, 1);
  await withNativeFixture(oversized, async (socket) => {
    await assert.rejects(exerciseIssuedSdkRead(socket), /E_NATIVE_READ_DENIED/);
  });
});
