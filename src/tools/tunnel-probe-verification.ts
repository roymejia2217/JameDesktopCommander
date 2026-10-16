import { isDeepStrictEqual } from 'node:util';
import { parseRuntimeBuildIdentity } from './runtime-build-identity.js';

/**
 * Pure caller-side verifier for one MCP tools/call response.
 * Transport authentication, nonce generation and deadline enforcement belong
 * to the actual MCP client, not this non-operational validator.
 */
export interface McpRoundTripRequest {
  challenge: string;
  expectedCommit: string;
  expectedPackageVersion: string;
  requestStartedAtMs: number;
  responseReceivedAtMs: number;
}

export type McpRoundTripVerification =
  | { kind: 'verified'; reason: 'correlated_mcp_response';
      runtimeInstanceId: string; sourceCommit: string; packageVersion: string }
  | { kind: 'hold'; reason:
      'invalid_request' | 'late_response' | 'invalid_response' |
      'challenge_mismatch' | 'unavailable_build' | 'unexpected_build' |
      'untrusted_observation_time' | 'instance_changed' | 'duplicate_challenge' };

const CHALLENGE = /^[0-9a-f]{32}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_CALL_MS = 30_000;
const ALLOWED_SERVER_SKEW_MS = 120_000;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function exactKeys(value: unknown, keys: readonly string[]): boolean {
  const object = record(value);
  return object !== null && Object.keys(object).length === keys.length &&
    Object.keys(object).every(key => keys.includes(key));
}

function validClock(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/** Do not accept timestamps masquerading as valid UTC by normalization. */
function canonicalUtcTimestamp(raw: unknown): number | null {
  if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(raw)) {
    return null;
  }
  const ms = Date.parse(raw);
  return Number.isFinite(ms) && new Date(ms).toISOString() === raw ? ms : null;
}

export function verifyMcpRoundTripResponse(
  request: McpRoundTripRequest,
  response: unknown,
): McpRoundTripVerification {
  if (!exactKeys(request, ['challenge', 'expectedCommit', 'expectedPackageVersion',
    'requestStartedAtMs', 'responseReceivedAtMs']) ||
      !CHALLENGE.test(request.challenge) || !COMMIT.test(request.expectedCommit) ||
      !VERSION.test(request.expectedPackageVersion) ||
      !validClock(request.requestStartedAtMs) || !validClock(request.responseReceivedAtMs) ||
      request.responseReceivedAtMs < request.requestStartedAtMs) {
    return { kind: 'hold', reason: 'invalid_request' };
  }
  if (request.responseReceivedAtMs - request.requestStartedAtMs > MAX_CALL_MS) {
    return { kind: 'hold', reason: 'late_response' };
  }

  const root = record(response);
  const observed = record(root?.structuredContent);
  if (!root || root.isError === true ||
      !exactKeys(observed, ['schemaVersion', 'kind', 'challenge',
        'runtimeInstanceId', 'observedAtUtc', 'runtimeBuild']) ||
      observed?.schemaVersion !== 1 ||
      observed?.kind !== 'mcp_tool_round_trip_only' ||
      typeof observed.runtimeInstanceId !== 'string' ||
      !UUID_V4.test(observed.runtimeInstanceId) ||
      !Array.isArray(root.content) || root.content.length !== 1 ||
      !exactKeys(root.content[0], ['type', 'text']) ||
      root.content[0].type !== 'text' ||
      typeof root.content[0].text !== 'string' ||
      root.content[0].text.length > 2048) {
    return { kind: 'hold', reason: 'invalid_response' };
  }

  let textual: unknown;
  try { textual = JSON.parse(root.content[0].text); }
  catch { return { kind: 'hold', reason: 'invalid_response' }; }
  if (!isDeepStrictEqual(textual, observed)) {
    return { kind: 'hold', reason: 'invalid_response' };
  }
  if (observed.challenge !== request.challenge) {
    return { kind: 'hold', reason: 'challenge_mismatch' };
  }
  const observedAt = canonicalUtcTimestamp(observed.observedAtUtc);
  if (observedAt === null ||
      observedAt < request.requestStartedAtMs - ALLOWED_SERVER_SKEW_MS ||
      observedAt > request.responseReceivedAtMs + ALLOWED_SERVER_SKEW_MS) {
    return { kind: 'hold', reason: 'untrusted_observation_time' };
  }
  if (record(observed.runtimeBuild)?.kind === 'unavailable') {
    return { kind: 'hold', reason: 'unavailable_build' };
  }
  let build;
  try { build = parseRuntimeBuildIdentity(observed.runtimeBuild); }
  catch { return { kind: 'hold', reason: 'invalid_response' }; }
  if (build.kind !== 'git' ||
      build.sourceCommit !== request.expectedCommit ||
      build.packageVersion !== request.expectedPackageVersion ||
      build.workspaceClean !== true) {
    return { kind: 'hold', reason: 'unexpected_build' };
  }
  return {
    kind: 'verified',
    reason: 'correlated_mcp_response',
    runtimeInstanceId: observed.runtimeInstanceId,
    sourceCommit: build.sourceCommit,
    packageVersion: build.packageVersion,
  };
}

/**
 * Both calls must have independently issued nonces and resolve from the same
 * server process. Even two verified calls are observations, NOT restart
 * permission, distributed availability certification or transport authentication.
 */
export function verifyMcpRoundTripPair(
  first: McpRoundTripRequest, firstResponse: unknown,
  second: McpRoundTripRequest, secondResponse: unknown,
): McpRoundTripVerification {
  if (first.challenge === second.challenge) {
    return { kind: 'hold', reason: 'duplicate_challenge' };
  }
  const a = verifyMcpRoundTripResponse(first, firstResponse);
  if (a.kind !== 'verified') return a;
  const b = verifyMcpRoundTripResponse(second, secondResponse);
  if (b.kind !== 'verified') return b;
  if (a.runtimeInstanceId !== b.runtimeInstanceId) {
    return { kind: 'hold', reason: 'instance_changed' };
  }
  return b;
}
