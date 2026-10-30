import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseCreateDirectoryRequest,
  parseOperationResult,
  AUTHORITY_PROTOCOL_VERSION,
} from '../dist/security/authority-operation-contract.js';

const valid = () => ({
  version: 1,
  kind: 'create-directory',
  requestId: '11111111-1111-4111-8111-111111111111',
  expectedEpoch: '18446744073709551615',
  rootRef: '0123456789abcdef0123456789abcdef',
  relativePath: 'project/nuevo',
});
const bad = { code: 'E_AUTHORITY_CONTRACT' };

test('C4c request contract accepts canonical bounded handle-relative operations', () => {
  assert.equal(AUTHORITY_PROTOCOL_VERSION, 1);
  const req = parseCreateDirectoryRequest(valid());
  assert.deepEqual(req, valid());
  assert.ok(Object.isFrozen(req));
  assert.equal(parseCreateDirectoryRequest({ ...valid(), relativePath: '科研/archivo' }).relativePath,
    '科研/archivo');
});
test('C4c rejects pathname approvals, invalid roots, missing fields and extras', () => {
  for (const value of [
    null, [], {}, { ...valid(), version: 2 },
    { ...valid(), kind: 'authorize-path' },
    { ...valid(), rootRef: 'C:/Users/Public' },
    { ...valid(), rootRef: 'ABCDEF0123456789ABCDEF0123456789' },
    { ...valid(), requestId: 'client-reused-token' },
    { ...valid(), rootPath: 'C:/sensitive' },
    { ...valid(), expectedEpoch: 1 },
    { ...valid(), expectedEpoch: '0' },
    { ...valid(), expectedEpoch: '01' },
    { ...valid(), expectedEpoch: '18446744073709551616' },
  ]) assert.throws(() => parseCreateDirectoryRequest(value), bad);
});
test('C4c rejects traversal, Windows device/ADS paths and oversized requests', () => {
  for (const relativePath of [
    '', '.', '..', 'a/../b', '/absolute', '//server/share', 'C:/drive',
    'a\\b', 'a//b', 'a/./b', 'a/', 'a:b', 'a?b', 'a*', 'a|b', 'a<b',
    'CON', 'con.txt', 'a/PRN', 'a/com1.log', 'LPT¹.log',
    'CONIN$', 'CONOUT$.txt', 'a/CONIN$',
    'trailing.', 'trailing ', 'a/space .', 'a/\u0000',
    'a'.repeat(256), 'a'.repeat(4097), 'a/'.repeat(65) + 'z',
  ]) assert.throws(() => parseCreateDirectoryRequest({ ...valid(), relativePath }), bad,
    'Unsafe relative path was accepted: ' + JSON.stringify(relativePath));
});
test('C4c rejects accessors and inherited request properties without executing them', () => {
  let executed = 0;
  const input = valid();
  Object.defineProperty(input, 'kind', { enumerable: true, get() {
    executed++;
    return 'create-directory';
  } });
  assert.throws(() => parseCreateDirectoryRequest(input), bad);
  assert.equal(executed, 0);
  const nested = { toJSON() { executed++; return '1'; } };
  assert.throws(() => parseCreateDirectoryRequest({ ...valid(), expectedEpoch: nested }), bad);
  assert.equal(executed, 0, 'Reject nonprimitive fields before serialization');
  assert.throws(() => parseCreateDirectoryRequest(
    Object.assign(Object.create({ kind: 'create-directory' }), valid())), bad);
});

test('C4c binds results to request identity and forbids replayable path grants', () => {
  const id = valid().requestId;
  const done = { version: 1, kind: 'operation-result', requestId: id,
    status: 'committed', committedEpoch: '18446744073709551615' };
  assert.deepEqual(parseOperationResult(done, id), done);
  assert.ok(Object.isFrozen(parseOperationResult(done, id)));
  const denied = { version: 1, kind: 'operation-result', requestId: id,
    status: 'rejected', errorCode: 'E_POLICY_STALE' };
  assert.deepEqual(parseOperationResult(denied, id), denied);
  for (const response of [
    { ...done, requestId: '22222222-2222-4222-8222-222222222222' },
    { ...done, rootPath: '/allowed' },
    { ...done, authorizationToken: 'replay-me' },
    { ...done, committedEpoch: '0' },
    { ...denied, committedEpoch: '2' },
    { ...denied, errorCode: 'ALLOW_ANY_PATH' },
    { ...done, status: 'rejected' },
    { ...denied, status: 'committed' },
  ]) assert.throws(() => parseOperationResult(response, id), bad);
});
