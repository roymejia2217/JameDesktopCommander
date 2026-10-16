/**
 * Strict result-publication acknowledgement from PostgREST UPDATE ... SELECT.
 * Never interpret HTTP 204, an empty array or network success as a write proof.
 */
export type RemoteResultPublication = 'confirmed' | 'fallback_confirmed';

export interface ResultUpdateResponse {
  data: unknown;
  error: { code?: string } | null;
}

export class RemoteResultUnconfirmedError extends Error {
  constructor() {
    super('Remote call result was not confirmed.');
    this.name = 'RemoteResultUnconfirmedError';
  }
}

export function confirmedSingleResultUpdate(
  response: ResultUpdateResponse,
  callId: string,
  expectedStatus: 'completed' | 'failed',
): void {
  if (response.error !== null ||
      !Array.isArray(response.data) ||
      response.data.length !== 1 ||
      !response.data[0] || typeof response.data[0] !== 'object' ||
      response.data[0].id !== callId ||
      response.data[0].status !== expectedStatus) {
    throw new RemoteResultUnconfirmedError();
  }
}

/**
 * Only PostgreSQL's deterministic invalid-text-byte rejection qualifies for
 * fallback. Transport errors, lost ACKs, timeouts and unknown DB errors may
 * have committed; issuing a fallback then could overwrite the actual result.
 */
export function definitelyRejectedResultBytes(response: ResultUpdateResponse): boolean {
  return response.error?.code === '22P05';
}
