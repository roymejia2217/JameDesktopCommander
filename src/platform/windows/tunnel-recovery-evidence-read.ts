import {
    evaluateRecoveryFencing,
    type RecoveryFencingEvidence,
    type RecoveryFencingRequest,
} from './tunnel-recovery-fencing.js';
import { parseDurableTunnelState, type DurableTunnelState } from './tunnel-desired-state-store.js';
import type { TunnelRecoveryLimits } from './tunnel-recovery-policy.js';

/** Read-only boundary; actual source authenticity requires a native Windows provider. */
export interface RecoveryEvidenceReader {
    readState(): Promise<DurableTunnelState>;
    readLease(): Promise<RecoveryFencingEvidence['lease']>;
    readTaskIdentity(): Promise<RecoveryFencingEvidence['task']>;
    readRuntime(): Promise<Pick<RecoveryFencingEvidence, 'process' | 'health' | 'network'>>;
    readClockMs(): Promise<number>;
}

export type RecoveryEvidenceProbe =
    | { kind: 'candidate_only'; reason: 'consistent_preflight' }
    | {
        kind: 'hold';
        reason: 'evidence_unavailable' | 'invalid_evidence' | 'evidence_changed' |
            'clock_regression' | 'preflight_rejected';
        preflightReason?: string;
        policyReason?: string;
    };

interface ReadSnapshot {
    evidence: RecoveryFencingEvidence;
    timeMs: number;
}

function exactKeys(input: unknown, expected: readonly string[]): boolean {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
    const actual = Object.keys(input);
    return actual.length === expected.length && actual.every((k) => expected.includes(k));
}

function validated(s: ReadSnapshot): ReadSnapshot {
    const e = s.evidence;
    if (!Number.isSafeInteger(s.timeMs) || s.timeMs < 0 ||
        !exactKeys(e, ['state', 'lease', 'task', 'process', 'health', 'network']) ||
        !exactKeys(e.lease, ['ownerId', 'epoch', 'status', 'expiresAtMs']) ||
        !exactKeys(e.task, ['digest', 'identityVerified']) ||
        !['running', 'absent', 'unknown'].includes(e.process) ||
        !['healthy', 'degraded', 'unknown'].includes(e.health) ||
        !['online', 'offline', 'unknown'].includes(e.network)) {
        throw new Error('Incomplete or invalid recovery observation.');
    }
    return {
        timeMs: s.timeMs,
        evidence: {
            state: parseDurableTunnelState(JSON.stringify(e.state)),
            lease: { ownerId: e.lease.ownerId, epoch: e.lease.epoch,
                status: e.lease.status, expiresAtMs: e.lease.expiresAtMs },
            task: { digest: e.task.digest, identityVerified: e.task.identityVerified },
            process: e.process, health: e.health, network: e.network,
        },
    };
}

async function readPass(reader: RecoveryEvidenceReader): Promise<ReadSnapshot> {
    const state = await reader.readState();
    const lease = await reader.readLease();
    const task = await reader.readTaskIdentity();
    const runtime = await reader.readRuntime();
    const timeMs = await reader.readClockMs();
    return validated({
        evidence: { state, lease, task,
            process: runtime.process, health: runtime.health, network: runtime.network },
        timeMs,
    });
}

function fingerprint(s: ReadSnapshot): string {
    const { state, lease, task, process, health, network } = s.evidence;
    return JSON.stringify([
        state.schemaVersion, state.revision, state.desired,
        state.retryAttempts, state.lastAttemptMs,
        lease.ownerId, lease.epoch, lease.status, lease.expiresAtMs,
        task.digest, task.identityVerified, process, health, network,
    ]);
}

/**
 * Detects observed changes in two sequential read passes; never owns a lease.
 * A candidate_only result is NOT permission to start a process or task.
 */
export async function probeRecoveryEvidenceReadOnly(
    request: Omit<RecoveryFencingRequest, 'nowMs'>,
    limits: TunnelRecoveryLimits,
    reader: RecoveryEvidenceReader,
): Promise<RecoveryEvidenceProbe> {
    if (!request || !limits || !reader ||
        ['readState', 'readLease', 'readTaskIdentity', 'readRuntime', 'readClockMs']
            .some((key) => typeof reader[key as keyof RecoveryEvidenceReader] !== 'function')) {
        return { kind: 'hold', reason: 'evidence_unavailable' };
    }
    let first: ReadSnapshot;
    let second: ReadSnapshot;
    try {
        first = await readPass(reader);
        second = await readPass(reader);
    } catch {
        return { kind: 'hold', reason: 'evidence_unavailable' };
    }
    if (second.timeMs < first.timeMs) {
        return { kind: 'hold', reason: 'clock_regression' };
    }
    if (fingerprint(first) !== fingerprint(second)) {
        return { kind: 'hold', reason: 'evidence_changed' };
    }
    try {
        const result = evaluateRecoveryFencing(
            { ...request, nowMs: second.timeMs }, second.evidence, limits,
        );
        if (result.kind !== 'eligible') {
            return {
                kind: 'hold', reason: 'preflight_rejected',
                preflightReason: result.reason,
                ...('policyReason' in result ? { policyReason: result.policyReason } : {}),
            };
        }
        return { kind: 'candidate_only', reason: 'consistent_preflight' };
    } catch {
        return { kind: 'hold', reason: 'invalid_evidence' };
    }
}
