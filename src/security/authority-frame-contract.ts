/**
 * T011-C4d - bounded canonical binary framing for a future trusted broker.
 * NOT a transport, authenticator, authority, or permission to perform I/O.
 * A future protected broker must validate OS caller identity before dispatch.
 */
import { TextDecoder } from 'node:util';
import {
  AuthorityContractError,
  parseCreateDirectoryRequest,
  parseReadFileRequest,
  parseOperationResult,
  type AuthorityOperationResult,
  type AuthorityRequest,
} from './authority-operation-contract.js';

export const MAX_AUTHORITY_FRAME_PAYLOAD_BYTES = 8192;
export const MAX_AUTHORITY_READ_PAYLOAD_BYTES = 1024 * 1024;
const LENGTH_BYTES = 4;
const READ_REPLY_HEADER_BYTES = 6;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export type AuthorityReadReply =
  | Readonly<{ version: 1; status: 'ok'; bytes: Buffer }>
  | Readonly<{ version: 1; status: 'denied' }>;

function deny(): never {
  throw new AuthorityContractError();
}

/** Decode one COMPLETE frame, never buffering arbitrary stream data. */
function payloadText(frame: unknown): string {
  if (!Buffer.isBuffer(frame) ||
      frame.byteLength < LENGTH_BYTES + 2 ||
      frame.byteLength > LENGTH_BYTES + MAX_AUTHORITY_FRAME_PAYLOAD_BYTES) deny();
  // One snapshot: no repeated reads from a possibly shared backing buffer.
  const bytes = Buffer.from(frame);
  const claimed = bytes.readUInt32BE(0);
  if (claimed < 2 || claimed > MAX_AUTHORITY_FRAME_PAYLOAD_BYTES ||
      claimed !== bytes.length - LENGTH_BYTES) deny();
  try {
    return decoder.decode(bytes.subarray(LENGTH_BYTES));
  } catch {
    return deny();
  }
}
/** Accept only well-formed Unicode scalar strings, not lone surrogates that
 * would be substituted by U+FFFD on native UTF-8 filesystem operations. */
function assertWellFormedValues(value: object): void {
  for (const field of Object.values(value)) {
    if (typeof field === 'string' &&
        Buffer.from(field, 'utf8').toString('utf8') !== field) deny();
  }
}

function buildFrame(payload: string): Buffer {
  const bytes = Buffer.from(payload, 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_AUTHORITY_FRAME_PAYLOAD_BYTES) deny();
  const frame = Buffer.allocUnsafe(LENGTH_BYTES + bytes.length);
  frame.writeUInt32BE(bytes.length, 0);
  bytes.copy(frame, LENGTH_BYTES);
  return frame;
}

function parseAuthorityRequest(input: unknown): Readonly<AuthorityRequest> {
  try {
    return parseCreateDirectoryRequest(input);
  } catch {
    return parseReadFileRequest(input);
  }
}

function requestJSON(req: Readonly<AuthorityRequest>): string {
  assertWellFormedValues(req);
  return JSON.stringify({
    version: req.version,
    kind: req.kind,
    requestId: req.requestId,
    expectedEpoch: req.expectedEpoch,
    rootRef: req.rootRef,
    relativePath: req.relativePath,
  });
}

function resultJSON(reply: AuthorityOperationResult): string {
  assertWellFormedValues(reply);
  if (reply.status === 'committed') {
    return JSON.stringify({
      version: reply.version, kind: reply.kind, requestId: reply.requestId,
      status: reply.status, committedEpoch: reply.committedEpoch,
    });
  }
  return JSON.stringify({
    version: reply.version, kind: reply.kind, requestId: reply.requestId,
    status: reply.status, errorCode: reply.errorCode,
  });
}
/** Encode only validated data, in a single deterministic property order. */
export function encodeAuthorityRequestFrame(input: unknown): Buffer {
  const req = parseAuthorityRequest(input);
  return buildFrame(requestJSON(req));
}

export function decodeAuthorityRequestFrame(frame: unknown): Readonly<AuthorityRequest> {
  try {
    const canonical = payloadText(frame);
    const req = parseAuthorityRequest(JSON.parse(canonical) as unknown);
    if (requestJSON(req) !== canonical) deny();
    return req;
  } catch {
    return deny();
  }
}

/** A result reports completed broker-side I/O only, never an access grant. */
export function encodeAuthorityResultFrame(
  input: unknown, requestId: string, expectedEpoch: string,
): Buffer {
  const reply = parseOperationResult(input, requestId, expectedEpoch);
  return buildFrame(resultJSON(reply));
}

export function decodeAuthorityResultFrame(
  frame: unknown, requestId: string, expectedEpoch: string,
): AuthorityOperationResult {
  try {
    const canonical = payloadText(frame);
    const reply = parseOperationResult(JSON.parse(canonical) as unknown, requestId, expectedEpoch);
    if (resultJSON(reply) !== canonical) deny();
    return reply;
  } catch {
    return deny();
  }
}

/** Decode the native one-request-per-connection read response.
 * Status 1 is a generic denial and MUST carry zero payload bytes. */
export function decodeAuthorityReadReplyFrame(frame: unknown): AuthorityReadReply {
  try {
    if (!Buffer.isBuffer(frame) ||
        frame.byteLength < READ_REPLY_HEADER_BYTES ||
        frame.byteLength > READ_REPLY_HEADER_BYTES + MAX_AUTHORITY_READ_PAYLOAD_BYTES) deny();
    const bytes = Buffer.from(frame);
    if (bytes[0] !== 1) deny();
    const status = bytes[1];
    const length = bytes.readUInt32BE(2);
    if (length > MAX_AUTHORITY_READ_PAYLOAD_BYTES ||
        length !== bytes.length - READ_REPLY_HEADER_BYTES) deny();
    if (status === 1) {
      if (length !== 0) deny();
      return Object.freeze({ version: 1, status: 'denied' });
    }
    if (status !== 0) deny();
    return Object.freeze({
      version: 1,
      status: 'ok',
      bytes: Buffer.from(bytes.subarray(READ_REPLY_HEADER_BYTES)),
    });
  } catch {
    return deny();
  }
}
