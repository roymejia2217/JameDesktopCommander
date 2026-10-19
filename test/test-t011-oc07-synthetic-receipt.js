import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  consumeSyntheticReceiptFrame,
  encodeSyntheticFixture,
  MAX_SYNTHETIC_FRAME_BYTES,
} from './fixtures/t011-oc07-synthetic-receipt.js';

const NOW = 1_800_000_000_000;
const sourceCommit = 'a'.repeat(40);
const recipientFingerprint = 'b'.repeat(64);
const serviceInstance = 'synthetic-scm-1';
const challenge = Buffer.alloc(32, 7).toString('base64url');
const valid = () => ({
  schemaVersion: 0,
  sourceCommit,
  serviceInstance,
  runAttempt: 1,
  recipientFingerprint,
  challenge,
  issuedAtMs: NOW - 1000,
  expiresAtMs: NOW + 1000,
});
const expectations = () => ({
  nowMs: NOW,
  sourceCommit,
  serviceInstance,
  runAttempt: 1,
  recipientFingerprint,
  challenge,
  consumedChallenges: new Set(),
});
const reject = (frame, options = expectations()) =>
  assert.throws(() => consumeSyntheticReceiptFrame(frame, options),
    /Synthetic receipt denied:/);

test('OC-07.2h synthetic frame: one canonical message is consumed only once', () => {
  const frame = encodeSyntheticFixture(valid());
  const context = expectations();
  assert.deepEqual(consumeSyntheticReceiptFrame(frame, context),
    { accepted: true, schemaVersion: 0 });
  assert.equal(context.consumedChallenges.size, 1);
  assert.throws(() => consumeSyntheticReceiptFrame(frame, context), /replay/);
});

test('OC-07.2h rejects duplicated or truncated frames and length disagreement', () => {
  const frame = encodeSyntheticFixture(valid());
  reject(Buffer.concat([frame, frame]));
  reject(frame.subarray(0, frame.length - 1));
  const overlong = Buffer.from(frame);
  overlong.writeUInt32BE(MAX_SYNTHETIC_FRAME_BYTES + 1, 0);
  reject(overlong);
  const short = Buffer.from(frame);
  short.writeUInt32BE(2, 0);
  reject(short);
  reject(Buffer.alloc(0));
  reject('not a buffer');
});

test('OC-07.2h rejects ambiguous, duplicate and noncanonical JSON', () => {
  const frame = encodeSyntheticFixture(valid());
  const text = frame.subarray(4).toString('utf8');
  for (const corrupted of [
    '{',
    'null',
    '[]',
    JSON.stringify({ ...valid(), extra: 1 }),
    text.replace(',"sourceCommit":', ',"schemaVersion":0,"sourceCommit":'),
    text.replace('{"schemaVersion"', '{ "schemaVersion"'),
    text.replace('"schemaVersion":0', '"schemaVersion":0.0'),
    JSON.stringify({ ...valid(), schemaVersion: 1 }),
  ]) {
    if (corrupted === text) continue;
    const bytes = Buffer.from(corrupted);
    const framed = Buffer.alloc(bytes.length + 4);
    framed.writeUInt32BE(bytes.length, 0);
    bytes.copy(framed, 4);
    reject(framed);
  }
  const invalid = Buffer.from(frame);
  invalid[9] = 0xff;
  reject(invalid);
});

test('OC-07.2h rejects wrong provenance, recipient and unsupported metadata', () => {
  for (const changed of [
    { sourceCommit: 'c'.repeat(40) },
    { recipientFingerprint: 'c'.repeat(64) },
    { serviceInstance: 'other-scm-2' },
    { runAttempt: 0 },
    { runAttempt: 1000 },
    { challenge: 'not-a-valid-challenge' },
    { issuedAtMs: NOW + 1 },
    { expiresAtMs: NOW },
    { expiresAtMs: NOW + 301_000 },
    { schemaVersion: 1 },
    { sourceCommit: 'abc' },
    { sourceCommit: sourceCommit.toUpperCase() },
    { recipientFingerprint: 'invalid' },
    { serviceInstance: '!' },
    { challenge: challenge.slice(0, 42) },
    { expiresAtMs: NOW - 2 },
    { issuedAtMs: -1 },
    { runAttempt: 1.5 },
  ]) reject(encodeSyntheticFixture({ ...valid(), ...changed }));
});

test('OC-07.2h failures do not consume a challenge or authorize next state', () => {
  const ctx = expectations();
  const invalid = encodeSyntheticFixture({ ...valid(), sourceCommit: 'c'.repeat(40) });
  reject(invalid, ctx);
  assert.equal(ctx.consumedChallenges.size, 0);
  assert.deepEqual(consumeSyntheticReceiptFrame(encodeSyntheticFixture(valid()), ctx),
    { accepted: true, schemaVersion: 0 });
  assert.equal(ctx.consumedChallenges.size, 1);
});

test('OC-07.2h verifier expectation fails closed when unauthenticated or missing', () => {
  assert.throws(() => consumeSyntheticReceiptFrame(
    encodeSyntheticFixture(valid()), undefined), /invalid verifier expectations/);
  reject(encodeSyntheticFixture(valid()), {
    ...expectations(), recipientFingerprint: 'not-a-key-fingerprint',
  });
  reject(encodeSyntheticFixture(valid()), {
    ...expectations(), consumedChallenges: null,
  });
});

test('OC-07.2h rejects a valid but different run attempt before consuming challenge', () => {
  const ctx = { ...expectations(), runAttempt: 1, challenge };
  const changed = encodeSyntheticFixture({ ...valid(), runAttempt: 2 });
  assert.throws(() => consumeSyntheticReceiptFrame(changed, ctx),
    /synthetic receipt denied/i);
  assert.equal(ctx.consumedChallenges.size, 0);
  assert.deepEqual(consumeSyntheticReceiptFrame(encodeSyntheticFixture(valid()), ctx),
    { accepted: true, schemaVersion: 0 });
});

test('OC-07.2h rejects a different canonical 32-byte challenge before consumption', () => {
  const ctx = { ...expectations(), runAttempt: 1, challenge };
  const otherChallenge = Buffer.alloc(32, 8).toString('base64url');
  const changed = encodeSyntheticFixture({ ...valid(), challenge: otherChallenge });
  assert.throws(() => consumeSyntheticReceiptFrame(changed, ctx),
    /synthetic receipt denied/i);
  assert.equal(ctx.consumedChallenges.size, 0);
  assert.deepEqual(consumeSyntheticReceiptFrame(encodeSyntheticFixture(valid()), ctx),
    { accepted: true, schemaVersion: 0 });
});

test('OC-07.2h requires expected attempt and issued challenge to be present and valid', () => {
  for (const override of [
    { runAttempt: undefined },
    { runAttempt: 0 },
    { runAttempt: 1.5 },
    { challenge: undefined },
    { challenge: 'malformed' },
  ]) {
    const ctx = { ...expectations(), runAttempt: 1, challenge, ...override };
    assert.throws(() => consumeSyntheticReceiptFrame(encodeSyntheticFixture(valid()), ctx),
      /synthetic receipt denied/i);
    assert.equal(ctx.consumedChallenges.size, 0);
  }
});
