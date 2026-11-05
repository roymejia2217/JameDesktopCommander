/**
 * Portable, read-only operator assessment of local tunnel evidence.
 * Local health and observed MCP handshakes never prove fresh remote delivery.
 * The only valid outcomes without a remote request/result witness are
 * degraded (observed fault) or unverified (insufficient evidence).
 */
export type TunnelControlPlaneProblem =
    | 'none' | 'credential_rejected' | 'permission_denied'
    | 'rate_limited' | 'server_error' | 'other_http_error' | 'unverified';

export interface TunnelLocalEvidence {
    localHealth: 'ready' | 'not_ready' | 'unverified';
    mcpInitializeObserved: boolean | null;
    toolDiscovery: 'observed_complete' | 'observed_incomplete' | 'unverified';
    controlPlaneProblem: TunnelControlPlaneProblem;
}

export type TunnelLocalReasonCode =
    | 'CONTROL_PLANE_CREDENTIAL_REJECTED' | 'CONTROL_PLANE_FORBIDDEN'
    | 'CONTROL_PLANE_RATE_LIMITED' | 'CONTROL_PLANE_SERVER_ERROR'
    | 'CONTROL_PLANE_HTTP_ERROR' | 'CONTROL_PLANE_UNVERIFIED'
    | 'LOCAL_NOT_READY' | 'LOCAL_READINESS_UNVERIFIED'
    | 'MCP_HANDSHAKE_UNOBSERVED' | 'MCP_TOOLS_LIST_UNVERIFIED'
    | 'REMOTE_ROUND_TRIP_UNVERIFIED';

export interface TunnelLocalOperability {
    kind: 'local_operability_v1';
    state: 'degraded' | 'unverified';
    reasonCode: TunnelLocalReasonCode;
    remoteRoundTrip: 'not_observed';
}

function verdict(
    state: TunnelLocalOperability['state'],
    reasonCode: TunnelLocalReasonCode,
): TunnelLocalOperability {
    return {
        kind: 'local_operability_v1',
        state,
        reasonCode,
        remoteRoundTrip: 'not_observed',
    };
}

export function assessLocalTunnelOperability(
    evidence: TunnelLocalEvidence,
): TunnelLocalOperability {
    // Verified local component faults take priority over missing remote proof.
    switch (evidence.controlPlaneProblem) {
        case 'credential_rejected':
            return verdict('degraded', 'CONTROL_PLANE_CREDENTIAL_REJECTED');
        case 'permission_denied':
            return verdict('degraded', 'CONTROL_PLANE_FORBIDDEN');

        case 'rate_limited':
            return verdict('degraded', 'CONTROL_PLANE_RATE_LIMITED');
        case 'server_error':
            return verdict('degraded', 'CONTROL_PLANE_SERVER_ERROR');
        case 'other_http_error':
            return verdict('degraded', 'CONTROL_PLANE_HTTP_ERROR');
        case 'none':
            break;
        default:
            // An unknown control plane must not mask a confirmed local outage.
            break;
    }
    if (evidence.localHealth === 'not_ready') {
        return verdict('degraded', 'LOCAL_NOT_READY');
    }
    if (evidence.controlPlaneProblem !== 'none') {
        return verdict('unverified', 'CONTROL_PLANE_UNVERIFIED');
    }
    if (evidence.localHealth !== 'ready') {
        return verdict('unverified', 'LOCAL_READINESS_UNVERIFIED');
    }
    if (evidence.mcpInitializeObserved !== true) {
        return verdict('unverified', 'MCP_HANDSHAKE_UNOBSERVED');
    }
    if (evidence.toolDiscovery !== 'observed_complete') {
        return verdict('unverified', 'MCP_TOOLS_LIST_UNVERIFIED');
    }
    return verdict('unverified', 'REMOTE_ROUND_TRIP_UNVERIFIED');
}

/**
 * Local systemd/client observations do not include fresh remote MCP proof.
 * Inactivity is a fact about the unit, not proof of an intentional stop.
 * This coarse lifecycle view is distinct from HTTP component diagnostics.
 */
export interface TunnelLocalLifecycleEvidence {
    active: boolean;
    enabled: boolean;
    healthy: boolean;
    controlPlanePoll: boolean;
}

export interface TunnelLocalLifecycleObservation {
    kind: 'local_lifecycle_only';
    state: 'inactive' | 'unverified';
    reasonCode:
        | 'SERVICE_INACTIVE' | 'SERVICE_NOT_ENABLED'
        | 'CONTROL_PLANE_POLL_UNVERIFIED' | 'LOCAL_HEALTH_UNVERIFIED'
        | 'LOCAL_EVIDENCE_CONFLICT' | 'REMOTE_ROUND_TRIP_UNVERIFIED';
    remoteRoundTrip: 'not_observed';
}

function lifecycleVerdict(
    state: TunnelLocalLifecycleObservation['state'],
    reasonCode: TunnelLocalLifecycleObservation['reasonCode'],
): TunnelLocalLifecycleObservation {
    return { kind: 'local_lifecycle_only', state, reasonCode,
        remoteRoundTrip: 'not_observed' };
}

export function assessTunnelLocalLifecycle(
    evidence: TunnelLocalLifecycleEvidence,
): TunnelLocalLifecycleObservation {
    if (!evidence ||
        typeof evidence.active !== 'boolean' ||
        typeof evidence.enabled !== 'boolean' ||
        typeof evidence.healthy !== 'boolean' ||
        typeof evidence.controlPlanePoll !== 'boolean' ||
        (!evidence.active && (evidence.healthy || evidence.controlPlanePoll)) ||
        (evidence.healthy && !evidence.controlPlanePoll)) {
        return lifecycleVerdict('unverified', 'LOCAL_EVIDENCE_CONFLICT');
    }

    if (!evidence.active) {
        return lifecycleVerdict('inactive', 'SERVICE_INACTIVE');
    }
    if (!evidence.enabled) {
        return lifecycleVerdict('unverified', 'SERVICE_NOT_ENABLED');
    }
    if (!evidence.controlPlanePoll) {
        return lifecycleVerdict('unverified', 'CONTROL_PLANE_POLL_UNVERIFIED');
    }
    if (!evidence.healthy) {
        return lifecycleVerdict('unverified', 'LOCAL_HEALTH_UNVERIFIED');
    }
    return lifecycleVerdict('unverified', 'REMOTE_ROUND_TRIP_UNVERIFIED');
}
