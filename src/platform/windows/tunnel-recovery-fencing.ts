import {
    decideTunnelRecovery,
    type NetworkState,
    type TunnelHealthState,
    type TunnelProcessState,
    type TunnelRecoveryLimits,
} from './tunnel-recovery-policy.js';
import {
    parseDurableTunnelState,
    type DurableTunnelState,
} from './tunnel-desired-state-store.js';

/** Candidate preflight only: no OS, filesystem, lease acquisition or task side effects. */
export interface RecoveryFencingRequest {
    controllerId: string;
    controllerEpoch: number;
    expectedStateRevision: number;
    expectedTaskDigest: string;
    nowMs: number;
}

export interface RecoveryFencingEvidence {
    state: DurableTunnelState;
    lease: {
        ownerId: string;
        epoch: number;
        status: 'held' | 'released' | 'unknown';
        expiresAtMs: number;
    };
    task: { digest: string; identityVerified: boolean };
    process: TunnelProcessState;
    health: TunnelHealthState;
    network: NetworkState;
}

export type RecoveryFencingDecision =
    | { kind: 'eligible'; reason: 'fenced_candidate' }
    | {
        kind: 'hold';
        reason:
            | 'revision_changed'
            | 'lease_unavailable'
            | 'lease_owner_changed'
            | 'lease_epoch_changed'
            | 'lease_expired'
            | 'task_identity_unverified'
            | 'task_identity_changed'
            | 'policy_rejected';
        policyReason?: string;
    };

const DIGEST = /^[a-f0-9]{64}$/;
const IDENTIFIER = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

function requirePositive(label: string, value: unknown): void {
    if (!Number.isSafeInteger(value) || (value as number) < 1) {
        throw new Error(`${label} must be a positive safe integer.`);
    }
}

function requireTimestamp(label: string, value: unknown): void {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
        throw new Error(`${label} must be a nonnegative safe integer.`);
    }
}

/**
 * A fresh, authenticated evidence provider must collect these values while
 * holding its independently enforced recovery lease. This pure function
 * cannot authenticate sources, extend leases or issue an execution token.
 */
export function evaluateRecoveryFencing(
    request: RecoveryFencingRequest,
    evidence: RecoveryFencingEvidence,
    limits: TunnelRecoveryLimits,
): RecoveryFencingDecision {
    if (!request || !evidence || !evidence.lease ||
        !evidence.task || !evidence.state) {
        throw new Error('Complete recovery request and evidence are required.');
    }
    if (!IDENTIFIER.test(request.controllerId) ||
        !IDENTIFIER.test(evidence.lease.ownerId)) {
        throw new Error('Recovery controller identifiers must be UUIDs.');
    }
    requirePositive('controllerEpoch', request.controllerEpoch);
    requirePositive('expectedStateRevision', request.expectedStateRevision);
    requirePositive('lease.epoch', evidence.lease.epoch);
    requireTimestamp('nowMs', request.nowMs);
    requireTimestamp('lease.expiresAtMs', evidence.lease.expiresAtMs);
    if (!DIGEST.test(request.expectedTaskDigest) ||
        !DIGEST.test(evidence.task.digest)) {
        throw new Error('Task identity requires a lowercase SHA-256 fingerprint.');
    }
    if (typeof evidence.task.identityVerified !== 'boolean') {
        throw new Error('Task identity verification must be explicit.');
    }
    if (!['held', 'released', 'unknown'].includes(evidence.lease.status)) {
        throw new Error('Unsupported recovery lease status.');
    }
    const state = parseDurableTunnelState(JSON.stringify(evidence.state));
    if (state.revision !== request.expectedStateRevision) {
        return { kind: 'hold', reason: 'revision_changed' };
    }
    if (evidence.lease.status !== 'held') {
        return { kind: 'hold', reason: 'lease_unavailable' };
    }
    if (evidence.lease.ownerId !== request.controllerId) {
        return { kind: 'hold', reason: 'lease_owner_changed' };
    }
    if (evidence.lease.epoch !== request.controllerEpoch) {
        return { kind: 'hold', reason: 'lease_epoch_changed' };
    }
    if (evidence.lease.expiresAtMs <= request.nowMs) {
        return { kind: 'hold', reason: 'lease_expired' };
    }
    if (!evidence.task.identityVerified) {
        return { kind: 'hold', reason: 'task_identity_unverified' };
    }
    if (evidence.task.digest !== request.expectedTaskDigest) {
        return { kind: 'hold', reason: 'task_identity_changed' };
    }
    const policy = decideTunnelRecovery({
        desired: state.desired,
        process: evidence.process,
        health: evidence.health,
        network: evidence.network,
        nowMs: request.nowMs,
        attempts: state.retryAttempts,
        lastAttemptMs: state.lastAttemptMs,
    }, limits);
    if (policy.kind !== 'start_candidate') {
        return {
            kind: 'hold', reason: 'policy_rejected',
            policyReason: policy.reason,
        };
    }
    return { kind: 'eligible', reason: 'fenced_candidate' };
}
