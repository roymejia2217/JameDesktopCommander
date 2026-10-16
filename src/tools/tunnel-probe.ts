import { randomUUID } from 'node:crypto';
import { TunnelProbeArgsSchema } from './schemas.js';
import { getRuntimeBuildIdentity, type RuntimeBuildIdentity } from './runtime-build-identity.js';

/**
 * Process-scoped correlation only. Neither UUID nor caller nonce is an
 * authentication credential, a recovery token or proof of transport security.
 */
const runtimeInstanceId = randomUUID();

export interface TunnelProbeObservation extends Record<string, unknown> {
  schemaVersion: 1;
  kind: 'mcp_tool_round_trip_only';
  challenge: string;
  runtimeInstanceId: string;
  observedAtUtc: string;
  runtimeBuild: RuntimeBuildIdentity;
}

export interface TunnelProbeResult {
  content: { type: 'text'; text: string }[];
  structuredContent?: TunnelProbeObservation;
  isError?: boolean;
}

/**
 * A genuinely new MCP tools/call response, correlated with a caller-supplied
 * unpredictable nonce. Cannot prove tools/list or remote-client reachability
 * until invoked by that remote client, and must never authorize a restart.
 */
export async function executeTunnelProbe(
  args: unknown,
  readIdentity: () => Promise<RuntimeBuildIdentity> = getRuntimeBuildIdentity,
  now: () => Date = () => new Date(),
): Promise<TunnelProbeResult> {
  const parsed = TunnelProbeArgsSchema.safeParse(args);
  if (!parsed.success) {
    return {
      isError: true,
      content: [{ type: 'text', text: 'Invalid MCP probe challenge.' }],
    };
  }
  const observation: TunnelProbeObservation = {
    schemaVersion: 1,
    kind: 'mcp_tool_round_trip_only',
    challenge: parsed.data.challenge,
    runtimeInstanceId,
    observedAtUtc: now().toISOString(),
    runtimeBuild: await readIdentity(),
  };
  return {
    content: [{ type: 'text', text: JSON.stringify(observation) }],
    structuredContent: observation,
  };
}
