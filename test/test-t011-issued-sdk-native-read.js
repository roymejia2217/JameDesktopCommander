import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:net';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { unlink } from 'node:fs/promises';
import { exerciseIssuedSdkRead, exerciseIssuedJdcRead } from './security/support/t011-issued-sdk-native-read.mjs';
import { createJdcServer } from '../dist/server.js';

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

test('real JDC dispatcher routes the fixed managed read across an OS stream', async () => {
  const bytes = Buffer.from('SERVICE_DOMAIN_BYTES');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  await withNativeFixture(Buffer.concat([Buffer.from('A'), length, bytes]),
    async (socket) => {
      assert.deepEqual(await exerciseIssuedJdcRead(socket, createJdcServer), bytes);
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

test('real JDC dispatcher preserves every UTF-8 byte, including a leading BOM', async () => {
  const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('SERVICE_DOMAIN_BYTES')]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  await withNativeFixture(Buffer.concat([Buffer.from('A'), length, bytes]),
    async (socket) => {
      const output = await exerciseIssuedJdcRead(socket, createJdcServer);
      assert.deepEqual(output, bytes);
      assert.equal(output.equals(Buffer.from('SERVICE_DOMAIN_BYTES')), false);
    });
});

test('issued JDC read distinguishes real transport failure from native rejection without leaking the socket path', async () => {
  const missing = process.platform === 'win32'
    ? `\\\\.\\pipe\\jdc-issued-sdk-missing-${randomUUID()}`
    : path.join(tmpdir(), `jdc-issued-sdk-missing-${randomUUID()}.sock`);
  await assert.rejects(exerciseIssuedJdcRead(missing, createJdcServer), error => {
    assert.equal(error.message, 'E_REAL_JDC_NATIVE_READ_DENIED: E_NATIVE_READ_TRANSPORT_ENOENT');
    assert.ok(!error.message.includes(missing));
    return true;
  });
  await withNativeFixture(Buffer.from('D'), async socket => {
    await assert.rejects(exerciseIssuedJdcRead(socket, createJdcServer), error => {
      assert.equal(error.message, 'E_REAL_JDC_NATIVE_READ_DENIED: E_NATIVE_READ_PROTOCOL');
      assert.ok(!error.message.includes(socket));
      return true;
    });
  });
});
