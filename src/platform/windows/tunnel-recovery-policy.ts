/**
 * Pure, non-operational recovery eligibility policy.
 * The caller must independently authenticate desired state, own an exclusive
 * recovery lease, and verify task/process identity before any lifecycle action.
 */
export type DesiredTunnelState = 'running' | 'stopped' | 'unknown';
export type TunnelProcessState = 'running' | 'absent' | 'unknown';
export type TunnelHealthState = 'healthy' | 'degraded' | 'unknown';
export type NetworkState = 'online' | 'offline' | 'unknown';

export interface TunnelRecoveryLimits {
    maxAttempts: number;
    baseDelayMs: number;
    maxDelayMs: number;
}

export interface TunnelRecoverySnapshot {
    desired: DesiredTunnelState;
    process: TunnelProcessState;
    health: TunnelHealthState;
    network: NetworkState;
    nowMs: number;
    attempts: number;
    lastAttemptMs: number | null;
}

export type TunnelRecoveryDecision =
    | { kind: 'healthy'; reason: 'healthy' }
    | { kind: 'start_candidate'; reason: 'missing_tunnel' }
    | {
        kind: 'hold';
        reason:
            | 'intentional_stop'
            | 'unknown_desired_state'
            | 'unknown_process_state'
            | 'unknown_health'
            | 'unknown_network'
            | 'network_offline'
            | 'inconsistent_observation'
            | 'inconsistent_attempt_history'
            | 'clock_regression'
            | 'backoff';
        retryAfterMs?: number;
    }
    | {
        kind: 'operator_required';
        reason:
            | 'running_while_stopped'
            | 'degraded_running_tunnel'
            | 'retry_budget_exhausted';
    };

function requireSafeInteger(
    label: string,
    value: unknown,
    minimum: number,
    maximum: number,
): number {
    if (!Number.isSafeInteger(value) || (value as number) < minimum ||
        (value as number) > maximum) {
        throw new Error(`${label} must be a safe integer in [${minimum}, ${maximum}].`);
    }
    return value as number;
}

function requireOneOf<T extends string>(
    label: string,
    value: T,
    allowed: readonly T[],
): void {
    if (!allowed.includes(value)) {
        throw new Error(`${label} has an unsupported value.`);
    }
}

export function decideTunnelRecovery(
    snapshot: TunnelRecoverySnapshot,
    limits: TunnelRecoveryLimits,
): TunnelRecoveryDecision {
    if (!snapshot || !limits) {
        throw new Error('Recovery snapshot and limits are required.');
    }
    requireOneOf('desired', snapshot.desired, ['running', 'stopped', 'unknown']);
    requireOneOf('process', snapshot.process, ['running', 'absent', 'unknown']);
    requireOneOf('health', snapshot.health, ['healthy', 'degraded', 'unknown']);
    requireOneOf('network', snapshot.network, ['online', 'offline', 'unknown']);
    requireSafeInteger('nowMs', snapshot.nowMs, 0, Number.MAX_SAFE_INTEGER);
    requireSafeInteger('attempts', snapshot.attempts, 0, 32);
    if (snapshot.lastAttemptMs !== null) {
        requireSafeInteger(
            'lastAttemptMs', snapshot.lastAttemptMs, 0, Number.MAX_SAFE_INTEGER,
        );
    }
    const maxAttempts = requireSafeInteger('maxAttempts', limits.maxAttempts, 0, 32);
    const baseDelayMs = requireSafeInteger('baseDelayMs', limits.baseDelayMs, 1000, 3600000);
    const maxDelayMs = requireSafeInteger('maxDelayMs', limits.maxDelayMs, baseDelayMs, 86400000);

    // Never recover unknown intent or reverse an explicit operator stop.
    if (snapshot.desired === 'unknown') {
        return { kind: 'hold', reason: 'unknown_desired_state' };
    }
    if (snapshot.desired === 'stopped') {
        return snapshot.process === 'running'
            ? { kind: 'operator_required', reason: 'running_while_stopped' }
            : { kind: 'hold', reason: 'intentional_stop' };
    }
    if (snapshot.process === 'unknown') {
        return { kind: 'hold', reason: 'unknown_process_state' };
    }
    if (snapshot.process === 'running') {
        if (snapshot.health === 'healthy') {
            return { kind: 'healthy', reason: 'healthy' };
        }
        return snapshot.health === 'degraded'
            ? { kind: 'operator_required', reason: 'degraded_running_tunnel' }
            : { kind: 'hold', reason: 'unknown_health' };
    }
    if (snapshot.health === 'healthy') {
        return { kind: 'hold', reason: 'inconsistent_observation' };
    }
    if (snapshot.network === 'unknown') {
        return { kind: 'hold', reason: 'unknown_network' };
    }
    if (snapshot.network === 'offline') {
        return { kind: 'hold', reason: 'network_offline' };
    }
    if (snapshot.attempts >= maxAttempts) {
        return { kind: 'operator_required', reason: 'retry_budget_exhausted' };
    }
    if ((snapshot.attempts === 0) !== (snapshot.lastAttemptMs === null)) {
        return { kind: 'hold', reason: 'inconsistent_attempt_history' };
    }
    if (snapshot.lastAttemptMs !== null) {
        if (snapshot.nowMs < snapshot.lastAttemptMs) {
            return { kind: 'hold', reason: 'clock_regression' };
        }
        const exponent = Math.min(snapshot.attempts - 1, 31);
        const delay = Math.min(maxDelayMs, baseDelayMs * 2 ** exponent);
        const remaining = Math.max(0, delay - (snapshot.nowMs - snapshot.lastAttemptMs));
        if (remaining > 0) {
            return { kind: 'hold', reason: 'backoff', retryAfterMs: remaining };
        }
    }
    // Eligibility is NOT authorization to start a task. No side effects occur.
    return { kind: 'start_candidate', reason: 'missing_tunnel' };
}
