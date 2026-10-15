import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRemoteCallReceipt } from '../dist/remote-device/remote-call-receipt.js';

const uuid = '7de2725a-58e6-40bc-b1bf-fde6c1f09119';

test('identical local receipt correlates phases without payload contents', () => {
  const times = [10, 12, 21, 25];
  const receipt = createRemoteCallReceipt(() => times.shift(), () => uuid);
  assert.equal(receipt('received'),
    `[JDC remote call] receipt=${uuid} stage=received elapsed_ms=2`);
  assert.equal(receipt('local_completed'),
    `[JDC remote call] receipt=${uuid} stage=local_completed elapsed_ms=11`);
  assert.equal(receipt('result_published'),
    `[JDC remote call] receipt=${uuid} stage=result_published elapsed_ms=15`);
});

test('stage allowlist rejects arbitrary arguments or result content', () => {
  const receipt = createRemoteCallReceipt(() => 100, () => uuid);
  for (const invalid of ['Bearer SECRET', 'args={password:xxx}', 'result=raw', '', null]) {
    assert.throws(() => receipt(invalid), /Invalid remote call receipt stage/);
  }
});

test('invalid identifiers and clocks fail closed', () => {
  assert.throws(() => createRemoteCallReceipt(() => 1, () => 'token'), /Invalid/);
  assert.throws(() => createRemoteCallReceipt(() => NaN, () => uuid), /Invalid/);
  const times = [1, Infinity];
  const receipt = createRemoteCallReceipt(() => times.shift(), () => uuid);
  assert.throws(() => receipt('received'), /Invalid/);
});

test('clock regression does not produce negative duration', () => {
  const times = [100, 95];
  const receipt = createRemoteCallReceipt(() => times.shift(), () => uuid);
  assert.match(receipt('execution_failed'), /elapsed_ms=0$/);
});
