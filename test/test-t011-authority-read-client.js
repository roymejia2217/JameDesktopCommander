import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  createIssuerReadClient,
  AuthorityReadTransportError,
} from './security/support/authority-read-client.mjs';
import {
  encodeAuthorityRequestFrame,
  decodeAuthorityReadReplyFrame,
  MAX_AUTHORITY_READ_PAYLOAD_BYTES,
} from '../dist/security/authority-frame-contract.js';
import { parseReadFileRequest, parseListDirectoryRequest } from '../dist/security/authority-operation-contract.js';
const { exchangeAuthorityReadFrame } = createIssuerReadClient({
  encodeAuthorityRequestFrame, decodeAuthorityReadReplyFrame,
  MAX_AUTHORITY_READ_PAYLOAD_BYTES, parseReadFileRequest,
});

const request = Object.freeze({
  version: 1,
  kind: 'read-file',
  requestId: '11111111-1111-4111-8111-111111111111',
  expectedEpoch: '1',
  rootRef: '0123456789abcdef0123456789abcdef',
  relativePath: 'inside.bin',
});
const reply = (bytes) => {
  const result = Buffer.alloc(6 + bytes.length);
  result[0] = 1;
  result[1] = 0;
  result.writeUInt32BE(bytes.length, 2);
  bytes.copy(result, 6);
  return result;
};
async function serve(t, handler) {
  const dir = await mkdtemp(path.join(tmpdir(), 'jdc-read-client-'));
  const address = process.platform === 'win32'
    ? String.raw`\\.\pipe\jdc-read-${randomUUID()}`
    : path.join(dir, 'issuer.sock');
  const active = new Set();
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    active.add(socket);
    socket.once('close', () => active.delete(socket));
    handler(socket);
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(address, resolve);
    });
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
  t.after(async () => {
    for (const socket of active) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  return address;
}

test('read reply retains exact bytes across fragmented native frames', async t => {
  const expected = Buffer.from([0, 255, 0x81, 42, 74, 68, 67, 10]);
  const address = await serve(t, socket => {
    const received = [];
    socket.on('data', chunk => {
      received.push(chunk);
      const frame = Buffer.concat(received);
      if (frame.length < 4 || frame.length < frame.readUInt32BE(0) + 4) return;
      assert.equal(frame.readUInt32BE(0), frame.length - 4);
      assert.equal(JSON.parse(frame.subarray(4).toString()).relativePath, 'inside.bin');
      const bytes = reply(expected);
      socket.write(bytes.subarray(0, 3));
      socket.end(bytes.subarray(3));
    });
  });
  const result = await exchangeAuthorityReadFrame(net.createConnection(address), request, 1000);
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.bytes, expected);
  expected.fill(1);
  assert.deepEqual(result.bytes, Buffer.from([0, 255, 0x81, 42, 74, 68, 67, 10]));
});

test('native denial cannot be misinterpreted as successful empty read', async t => {
  const address = await serve(t, socket => socket.once('data', () => socket.end(Buffer.from([1, 1, 0, 0, 0, 0]))));
  const result = await exchangeAuthorityReadFrame(net.createConnection(address), request, 1000);
  assert.deepEqual(result, { version: 1, status: 'denied' });
});

test('oversized native response denies before buffering unbounded bytes', async t => {
  const address = await serve(t, socket => socket.once('data', () => socket.end(Buffer.alloc(1024 * 1024 + 7))));
  await assert.rejects(
    exchangeAuthorityReadFrame(net.createConnection(address), request, 1000),
    error => error instanceof AuthorityReadTransportError && error.code === 'E_AUTHORITY_REPLY_INVALID',
  );
});

test('truncated response fails closed', async t => {
  const address = await serve(t, socket => socket.once('data', () => socket.end(Buffer.from([1, 0, 0, 0, 0, 8]))));
  await assert.rejects(
    exchangeAuthorityReadFrame(net.createConnection(address), request, 1000),
    error => error instanceof AuthorityReadTransportError && error.code === 'E_AUTHORITY_REPLY_INVALID',
  );
});

test('nonresponsive endpoint is rejected by a wall-clock deadline', async t => {
  const address = await serve(t, socket => socket.once('data', () => {}));
  await assert.rejects(
    exchangeAuthorityReadFrame(net.createConnection(address), request, 150),
    error => error instanceof AuthorityReadTransportError && error.code === 'E_AUTHORITY_TIMEOUT',
  );
});
test('shared authority transport validates typed directory listing without granting paths', async t => {
  const address = await serve(t, socket => {
    const chunks = [];
    let replied = false;
    socket.on('data', chunk => {
      if (replied) return;
      chunks.push(chunk);
      const frame = Buffer.concat(chunks);
      if (frame.length < 4 || frame.length < frame.readUInt32BE(0) + 4) return;
      assert.equal(frame.length, frame.readUInt32BE(0) + 4);
      const body = JSON.parse(frame.subarray(4).toString('utf8'));
      assert.equal(body.kind, 'list-directory');
      assert.equal(body.relativePath, 'nested');
      replied = true;
      socket.end(reply(Buffer.from('["a.txt","z.txt"]')));
    });
  });
  const client = createIssuerReadClient({
    encodeAuthorityRequestFrame,
    decodeAuthorityReadReplyFrame,
    MAX_AUTHORITY_READ_PAYLOAD_BYTES,
    parseReadFileRequest,
    parseListDirectoryRequest,
  });
  const listing = { ...request, kind: 'list-directory', relativePath: 'nested' };
  assert.deepEqual(
    await client.exchangeAuthorityListFrame(net.createConnection(address), listing, 1000),
    { version: 1, status: 'ok', entries: ['a.txt', 'z.txt'] },
  );
  await assert.rejects(
    client.exchangeAuthorityListFrame(net.createConnection(address), { ...listing, kind: 'create-directory' }, 1000),
    error => error instanceof AuthorityReadTransportError && error.code === 'E_AUTHORITY_REQUEST_INVALID',
  );
});
