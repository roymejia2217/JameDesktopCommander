import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  encodeAuthorityRequestFrame, decodeAuthorityRequestFrame,
  encodeAuthorityResultFrame, decodeAuthorityResultFrame,
  decodeAuthorityReadReplyFrame,
} from '../dist/security/authority-frame-contract.js';

const request = () => ({
  version: 1, kind: 'create-directory',
  requestId: '11111111-1111-4111-8111-111111111111',
  expectedEpoch: '18446744073709551615',
  rootRef: '0123456789abcdef0123456789abcdef',
  relativePath: '科研/dir',
});
const readRequest = () => ({ ...request(), kind: 'read-file', relativePath: '科研/data.bin' });
const committed = () => ({
  version: 1, kind: 'operation-result', requestId: request().requestId,
  status: 'committed', committedEpoch: '18446744073709551615',
});
const denied = () => ({
  version: 1, kind: 'operation-result', requestId: request().requestId,
  status: 'rejected', errorCode: 'E_POLICY_STALE',
});
const bad = { code: 'E_AUTHORITY_CONTRACT' };
const frame = (body) => {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const output = Buffer.allocUnsafe(4 + bytes.length);
  output.writeUInt32BE(bytes.length, 0);
  bytes.copy(output, 4);
  return output;
};
test('C4d canonical round-trip for requests, committed and rejected results', () => {
  const encoded = encodeAuthorityRequestFrame(request());
  assert.ok(Buffer.isBuffer(encoded));
  assert.equal(encoded.readUInt32BE(0), encoded.length - 4);
  assert.deepEqual(decodeAuthorityRequestFrame(encoded), request());
  assert.ok(Object.isFrozen(decodeAuthorityRequestFrame(encoded)));
  const shuffled = { relativePath: '科研/dir', ...request() };
  assert.ok(encodeAuthorityRequestFrame(shuffled).equals(encoded),
    'Field order from untrusted objects must never affect canonical bytes');
  const readWire = encodeAuthorityRequestFrame(readRequest());
  assert.deepEqual(decodeAuthorityRequestFrame(readWire), readRequest());
  for (const result of [committed(), denied()]) {
    const wire = encodeAuthorityResultFrame(result, request().requestId, request().expectedEpoch);
    assert.deepEqual(decodeAuthorityResultFrame(wire, request().requestId, request().expectedEpoch), result);
    assert.ok(Object.isFrozen(decodeAuthorityResultFrame(wire, request().requestId, request().expectedEpoch)));
    assert.equal(wire.readUInt32BE(0), wire.length - 4);
  }
});

test('C4d read reply preserves binary bytes and represents denial without payload', () => {
  const payload = Buffer.from([0, 255, 0x81, 42]);
  const ok = Buffer.alloc(6 + payload.length);
  ok[0] = 1;
  ok[1] = 0;
  ok.writeUInt32BE(payload.length, 2);
  payload.copy(ok, 6);
  const decoded = decodeAuthorityReadReplyFrame(ok);
  assert.equal(decoded.status, 'ok');
  assert.deepEqual(decoded.bytes, payload);
  assert.notEqual(decoded.bytes, ok.subarray(6), 'decoder must return an owned payload snapshot');
  ok[6] = 99;
  assert.deepEqual(decoded.bytes, payload, 'later mutation of transport memory must not alter result bytes');

  assert.deepEqual(
    decodeAuthorityReadReplyFrame(Buffer.from([1, 1, 0, 0, 0, 0])),
    { version: 1, status: 'denied' },
  );
  for (const malformed of [
    Buffer.from([1, 0, 0, 0, 0]),
    Buffer.from([2, 1, 0, 0, 0, 0]),
    Buffer.from([1, 2, 0, 0, 0, 0]),
    Buffer.from([1, 1, 0, 0, 0, 1, 7]),
    Buffer.from([1, 0, 0, 0, 0, 2, 7]),
    Buffer.alloc(6 + 1024 * 1024 + 1),
  ]) assert.throws(() => decodeAuthorityReadReplyFrame(malformed), bad);
});
test('C4d denies missing, trailing, oversized, nested, and mismatched frames', () => {
  const good = encodeAuthorityRequestFrame(request());
  const wrong = [
    null, undefined, new Uint8Array(good), Buffer.alloc(0),
    good.subarray(0, 3), good.subarray(0, 4), good.subarray(0, good.length - 1),
    Buffer.concat([good, Buffer.from([0])]),
    Buffer.concat([good, good]),
    Buffer.alloc(4), Buffer.alloc(8197),
  ];
  for (const value of wrong) assert.throws(() => decodeAuthorityRequestFrame(value), bad);
  const invalidSize = Buffer.from(good);
  invalidSize.writeUInt32BE(invalidSize.readUInt32BE(0) + 1, 0);
  assert.throws(() => decodeAuthorityRequestFrame(invalidSize), bad);
  const zero = Buffer.from(good);
  zero.writeUInt32BE(0, 0);
  assert.throws(() => decodeAuthorityRequestFrame(zero), bad);
  const huge = Buffer.from(good);
  huge.writeUInt32BE(8193, 0);
  assert.throws(() => decodeAuthorityRequestFrame(huge), bad);
});
test('C4d refuses duplicate fields and noncanonical JSON encodings', () => {
  const canonical = JSON.stringify(request());
  const malformed = [
    ' ' + canonical, canonical + '\n', canonical.replace(',', ', '),
    canonical.replace('"version":1', '"version":1.0'),
    canonical.replace('"version":1', '"version":1,"version":1'),
    canonical.replace('"version":1', '"unknown":2,"version":1'),
    canonical.replace('"kind"', '"\\u006bind"'),
    '\ufeff' + canonical,
    '[1,2,3]',
    '{"version":1',
  ];
  for (const raw of malformed) {
    assert.throws(() => decodeAuthorityRequestFrame(frame(raw)), bad, raw.slice(0, 110));
  }
  const wrongOrder = JSON.stringify({ ...{ relativePath: request().relativePath },
    version: 1, kind: 'create-directory', requestId: request().requestId,
    expectedEpoch: request().expectedEpoch, rootRef: request().rootRef });
  assert.throws(() => decodeAuthorityRequestFrame(frame(wrongOrder)), bad);
  assert.throws(() => decodeAuthorityRequestFrame(frame(Buffer.from([0xc3, 0x28]))), bad);
  assert.throws(() => decodeAuthorityRequestFrame(frame(Buffer.from([0xff, 0xfe]))), bad);
});
test('C4d refuses ambiguous Unicode and forged response metadata', () => {
  assert.throws(() => encodeAuthorityRequestFrame({ ...request(), relativePath: 'a\ud800' }), bad);
  const raw = JSON.stringify({ ...request(), relativePath: 'a\ud800' });
  assert.throws(() => decodeAuthorityRequestFrame(frame(raw)), bad);
  const done = encodeAuthorityResultFrame(committed(), request().requestId, request().expectedEpoch);
  assert.throws(() => decodeAuthorityResultFrame(done,
    '22222222-2222-4222-8222-222222222222', request().expectedEpoch), bad);
  const forged = JSON.stringify({ ...committed(), approvedPath: 'C:/outside' });
  assert.throws(() => decodeAuthorityResultFrame(frame(forged), request().requestId, request().expectedEpoch), bad);
  assert.throws(() => encodeAuthorityResultFrame({ ...denied(), approvedPath: '/tmp' },
    request().requestId, request().expectedEpoch), bad);
  const duplicatedStatus = JSON.stringify(committed()).replace(
    '"status":"committed"', '"status":"committed","status":"committed"');
  assert.throws(() => decodeAuthorityResultFrame(frame(duplicatedStatus),
    request().requestId, request().expectedEpoch), bad);
});

test('C4d fails closed before invoking untrusted serializers or prototype hooks', () => {
  let executed = 0;
  const unsafe = { ...request(), relativePath: { toJSON() { executed++; return 'ok'; } } };
  assert.throws(() => encodeAuthorityRequestFrame(unsafe), bad);
  assert.equal(executed, 0);
  const field = request();
  Object.defineProperty(field, 'requestId', { enumerable: true, get() { executed++; return request().requestId; } });
  assert.throws(() => encodeAuthorityRequestFrame(field), bad);
  assert.equal(executed, 0);
});

test('C4d rejects an epoch-swapped committed frame before the caller accepts success', () => {
  const req = request();
  const wire = frame(JSON.stringify(committed()));
  assert.deepEqual(decodeAuthorityResultFrame(wire, req.requestId, req.expectedEpoch), committed());
  assert.throws(() => decodeAuthorityResultFrame(wire, req.requestId, '7'), bad);
  assert.throws(() => decodeAuthorityResultFrame(wire, req.requestId), bad);
  assert.throws(() => encodeAuthorityResultFrame(committed(), req.requestId, '7'), bad);
});
