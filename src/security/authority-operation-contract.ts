/**
 * T011-C4c experimental DATA contract for a future separately protected broker.
 * This validator is NOT an authority, a credential, an IPC transport, or a
 * revocation protocol. Never use its output to reopen filesystem pathnames.
 */
export const AUTHORITY_PROTOCOL_VERSION = 1 as const;
const MAX_MESSAGE_BYTES = 8192;
const MAX_RELATIVE_BYTES = 4096;
const MAX_U64 = 18446744073709551615n;
const requestIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const rootReferencePattern = /^[0-9a-f]{32}$/;
const epochPattern = /^[1-9][0-9]{0,19}$/;
const invalidPathCharacter = /[\\\\:*?"<>|\u0000-\u001f\u007f]/u;
const reservedDevice = /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i;

export type AuthorityRejectionCode =
  | 'E_POLICY_STALE' | 'E_POLICY_UNAVAILABLE' | 'E_AUTH_REQUIRED'
  | 'E_REQUEST_REJECTED' | 'E_OPERATION_FAILED' | 'E_OPERATION_CANCELLED';

export interface CreateDirectoryAuthorityRequest {
  readonly version: 1;
  readonly kind: 'create-directory';
  readonly requestId: string;
  readonly expectedEpoch: string;
  readonly rootRef: string;
  readonly relativePath: string;
}
export type AuthorityOperationResult =
  | Readonly<{
    version: 1;
    kind: 'operation-result';
    requestId: string;
    status: 'committed';
    committedEpoch: string;
  }>
  | Readonly<{
    version: 1;
    kind: 'operation-result';
    requestId: string;
    status: 'rejected';
    errorCode: AuthorityRejectionCode;
  }>;

export class AuthorityContractError extends Error {
  readonly code = 'E_AUTHORITY_CONTRACT';
  constructor() {
    super('Invalid authority protocol data');
    this.name = 'AuthorityContractError';
  }
}

function record(input: unknown, expected: readonly string[]): Record<string, unknown> {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new AuthorityContractError();
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AuthorityContractError();
  }
  const entries = Object.getOwnPropertyDescriptors(input);
  if (Object.keys(entries).length !== expected.length ||
      expected.some(key => !Object.prototype.hasOwnProperty.call(entries, key))) {
    throw new AuthorityContractError();
  }
  for (const descriptor of Object.values(entries)) {
    if (!Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
        descriptor.enumerable !== true ||
        (typeof descriptor.value !== 'string' && typeof descriptor.value !== 'number')) {
      throw new AuthorityContractError();
    }
  }
  const source = input as Record<string, unknown>;
  if (Buffer.byteLength(JSON.stringify(source), 'utf8') > MAX_MESSAGE_BYTES) {
    throw new AuthorityContractError();
  }
  return source;
}

function canonicalEpoch(value: unknown): value is string {
  return typeof value === 'string' && epochPattern.test(value) &&
    BigInt(value) <= MAX_U64;
}
function requestId(value: unknown): value is string {
  return typeof value === 'string' && requestIdPattern.test(value);
}
function pathIsSafe(value: unknown): value is string {
  if (typeof value !== 'string' || !value ||
      Buffer.byteLength(value, 'utf8') > MAX_RELATIVE_BYTES) return false;
  const parts = value.split('/');
  return parts.length <= 64 && parts.every(part =>
    part !== '' && part !== '.' && part !== '..' &&
    !part.endsWith('.') && !part.endsWith(' ') &&
    !invalidPathCharacter.test(part) && !reservedDevice.test(part) &&
    Buffer.byteLength(part, 'utf8') <= 255);
}

/** Validate data shape only; the protected authority must authenticate caller
 * identity and perform the operation on pinned OS handles itself. */
export function parseCreateDirectoryRequest(input: unknown): Readonly<CreateDirectoryAuthorityRequest> {
  try {
    const obj = record(input, ['version', 'kind', 'requestId', 'expectedEpoch',
      'rootRef', 'relativePath']);
    if (obj.version !== 1 || obj.kind !== 'create-directory' ||
        !requestId(obj.requestId) || !canonicalEpoch(obj.expectedEpoch) ||
        typeof obj.rootRef !== 'string' || !rootReferencePattern.test(obj.rootRef) ||
        !pathIsSafe(obj.relativePath)) throw new AuthorityContractError();
    return Object.freeze({ ...obj }) as unknown as Readonly<CreateDirectoryAuthorityRequest>;
  } catch {
    throw new AuthorityContractError();
  }
}
/** A committed result is notification of completed broker-side I/O, never
 * permission for the untrusted Node process to perform subsequent I/O. */
export function parseOperationResult(
  input: unknown, expectedRequestId: string,
): AuthorityOperationResult {
  try {
    if (!requestId(expectedRequestId)) throw new AuthorityContractError();
    if (input === null || typeof input !== 'object' || Array.isArray(input)) {
      throw new AuthorityContractError();
    }
    const status = Object.getOwnPropertyDescriptor(input, 'status');
    if (!status || !Object.prototype.hasOwnProperty.call(status, 'value')) {
      throw new AuthorityContractError();
    }
    const committed = status.value === 'committed';
    const rejected = status.value === 'rejected';
    if (!committed && !rejected) throw new AuthorityContractError();
    const obj = record(input, ['version', 'kind', 'requestId', 'status',
      committed ? 'committedEpoch' : 'errorCode']);
    if (obj.version !== 1 || obj.kind !== 'operation-result' ||
        obj.requestId !== expectedRequestId) throw new AuthorityContractError();
    if (committed && !canonicalEpoch(obj.committedEpoch)) throw new AuthorityContractError();
    if (rejected && !rejectionCodes.has(obj.errorCode)) throw new AuthorityContractError();
    return Object.freeze({ ...obj }) as AuthorityOperationResult;
  } catch {
    throw new AuthorityContractError();
  }
}
const rejectionCodes: ReadonlySet<unknown> = new Set<AuthorityRejectionCode>([
  'E_POLICY_STALE', 'E_POLICY_UNAVAILABLE', 'E_AUTH_REQUIRED',
  'E_REQUEST_REJECTED', 'E_OPERATION_FAILED', 'E_OPERATION_CANCELLED',
]);
