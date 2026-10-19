// Synthetic, test-only frame validator for OC-07.2h; NOT an SCM transport.
// This accepts invented identifiers ONLY: no native token data, IPC, keys or egress.
import { TextDecoder } from 'node:util';

export const MAX_SYNTHETIC_FRAME_BYTES = 1024;
const decoder = new TextDecoder('utf-8', { fatal: true });
const FIELDS = [
  'schemaVersion',
  'sourceCommit',
  'serviceInstance',
  'runAttempt',
  'recipientFingerprint',
  'challenge',
  'issuedAtMs',
  'expiresAtMs',
];

function deny(reason) {
  throw new Error(`Synthetic receipt denied: ${reason}`);
}

function validHex(value, bytes) {
  return typeof value === 'string' &&
    new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value);
}

function validChallenge(value) {
  return typeof value === 'string' &&
    /^[A-Za-z0-9_-]{43}$/.test(value) &&
    Buffer.from(value, 'base64url').length === 32 &&
    Buffer.from(value, 'base64url').toString('base64url') === value;
}

/**
 * Validate one untrusted, length-prefixed, canonical synthetic frame.
 * The caller-supplied expectations are TEST fixtures, NOT authentication.
 * @param {Buffer} frame
 * @param {{
 *  nowMs: number,
 *  sourceCommit: string,
 *  serviceInstance: string,
 *  runAttempt: number,
 *  recipientFingerprint: string,
 *  challenge: string,
 *  consumedChallenges: Set<string>,
 * }} expected
 */
export function consumeSyntheticReceiptFrame(frame, expected) {
  if (!Buffer.isBuffer(frame) || frame.length < 5) deny('invalid frame');
  if (frame.length > MAX_SYNTHETIC_FRAME_BYTES + 4) deny('oversized frame');
  const declared = frame.readUInt32BE(0);
  if (declared < 2 || declared > MAX_SYNTHETIC_FRAME_BYTES ||
      frame.length !== declared + 4) deny('framing mismatch');
  let text;
  try {
    text = decoder.decode(frame.subarray(4));
  } catch {
    deny('invalid UTF-8');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    deny('invalid JSON');
  }
  // Exact canonical JSON rejects duplicate keys, alternate encodings,
  // inconsistent field order, whitespace and ambiguous encodings.
  if (typeof value !== 'object' || value === null ||
      Array.isArray(value) || JSON.stringify(value) !== text) {
    deny('noncanonical JSON');
  }
  if (Object.keys(value).length !== FIELDS.length ||
      FIELDS.some((field, index) => Object.keys(value)[index] !== field)) {
    deny('unknown or missing fields');
  }
  if (value.schemaVersion !== 0) deny('unsupported synthetic schema');
  if (!validHex(value.sourceCommit, 20) ||
      typeof value.serviceInstance !== 'string' ||
      !/^[a-z0-9-]{6,64}$/.test(value.serviceInstance) ||
      !Number.isSafeInteger(value.runAttempt) ||
      value.runAttempt < 1 || value.runAttempt > 999 ||
      !validHex(value.recipientFingerprint, 32)) {
    deny('malformed synthetic metadata');
  }
  if (!validChallenge(value.challenge)) {
    deny('invalid challenge encoding');
  }
  if (!Number.isSafeInteger(value.issuedAtMs) ||
      !Number.isSafeInteger(value.expiresAtMs) ||
      value.issuedAtMs < 0 ||
      value.expiresAtMs <= value.issuedAtMs ||
      value.expiresAtMs - value.issuedAtMs > 300_000) {
    deny('invalid lifetime');
  }
  if (!expected || !Number.isSafeInteger(expected.nowMs) ||
      expected.nowMs < 0 ||
      !(expected.consumedChallenges instanceof Set) ||
      !validHex(expected.sourceCommit, 20) ||
      !validHex(expected.recipientFingerprint, 32) ||
      typeof expected.serviceInstance !== 'string' ||
      !/^[a-z0-9-]{6,64}$/.test(expected.serviceInstance) ||
      !Number.isSafeInteger(expected.runAttempt) ||
      expected.runAttempt < 1 || expected.runAttempt > 999 ||
      !validChallenge(expected.challenge)) {
    deny('invalid verifier expectations');
  }
  if (value.sourceCommit !== expected.sourceCommit ||
      value.serviceInstance !== expected.serviceInstance ||
      value.runAttempt !== expected.runAttempt ||
      value.recipientFingerprint !== expected.recipientFingerprint ||
      value.challenge !== expected.challenge) {
    deny('provenance, run attempt or challenge mismatch');
  }
  if (value.issuedAtMs > expected.nowMs ||
      value.expiresAtMs <= expected.nowMs) deny('stale or future challenge');
  const replayKey = `${value.serviceInstance}:${value.challenge}`;
  if (expected.consumedChallenges.has(replayKey)) deny('replay');
  expected.consumedChallenges.add(replayKey);
  return Object.freeze({ accepted: true, schemaVersion: 0 });
}

// Fixture encoder deliberately has no production-facing export or transport.
// Tests can construct bad frames independently to exercise all parser gates.
export function encodeSyntheticFixture(value) {
  const bytes = Buffer.from(JSON.stringify(value), 'utf8');
  const frame = Buffer.allocUnsafe(4 + bytes.length);
  frame.writeUInt32BE(bytes.length, 0);
  bytes.copy(frame, 4);
  return frame;
}
