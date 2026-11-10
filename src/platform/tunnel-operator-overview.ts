import { assessLocalTunnelOperability, type TunnelLocalReasonCode } from './tunnel-local-operability.js';
import type { TunnelFunctionalDiagnostics } from './tunnel-functional-diagnostics.js';
import type { WindowsTunnelStatus } from './windows/tunnel-status.js';

/** Versioned, read-only and deliberately secret-free UX payload. */
export interface TunnelOperatorOverviewV1 {
    kind: 'tunnel_operator_overview_v1';
    platform: 'win32';
    capabilities: 'read_only';
    observedAt: string;
    taskRegistration: 'observed' | 'unverified';
    localHealth: 'ready' | 'not_ready' | 'unverified';
    mcpInitialize: 'observed' | 'not_observed' | 'unverified';
    toolDiscovery: 'observed_complete' | 'observed_incomplete' | 'unverified';
    controlPlane: TunnelFunctionalDiagnostics['controlPlaneProblem'];
    remoteDelivery: 'not_observed';
    verdict: { state: 'degraded' | 'unverified';
        reasonCode: TunnelLocalReasonCode | 'TASK_STATUS_UNAVAILABLE' |
            'CLIENT_PROVENANCE_UNVERIFIED' |
            'LOCAL_DIAGNOSTICS_UNAVAILABLE' | 'LOCAL_EVIDENCE_CONFLICT' };
}
function unavailable(
    observedAt: string,
    reasonCode: 'TASK_STATUS_UNAVAILABLE' | 'CLIENT_PROVENANCE_UNVERIFIED' |
        'LOCAL_DIAGNOSTICS_UNAVAILABLE' | 'LOCAL_EVIDENCE_CONFLICT',
    taskRegistration: TunnelOperatorOverviewV1['taskRegistration'],
    localHealth: TunnelOperatorOverviewV1['localHealth'],
): TunnelOperatorOverviewV1 {
    return {
        kind: 'tunnel_operator_overview_v1', platform: 'win32',
        capabilities: 'read_only', observedAt, taskRegistration,
        localHealth, mcpInitialize: 'unverified',
        toolDiscovery: 'unverified', controlPlane: 'unverified',
        remoteDelivery: 'not_observed',
        verdict: { state: 'unverified', reasonCode },
    };
}

/** Never expose the source task XML, profile paths or provider message. */
export function projectWindowsOperatorOverview(
    status: WindowsTunnelStatus | null,
    diagnostic: TunnelFunctionalDiagnostics | null,
    now: Date = new Date(),
    taskObservedWithoutClient = false,
): TunnelOperatorOverviewV1 {
    const observedAt = now.toISOString();
    if (!status || status.task?.registered !== true) {
        return unavailable(observedAt, taskObservedWithoutClient
            ? 'CLIENT_PROVENANCE_UNVERIFIED' : 'TASK_STATUS_UNAVAILABLE',
        taskObservedWithoutClient ? 'observed' : 'unverified', 'unverified');
    }
    const health = status.health;
    const localHealth: TunnelOperatorOverviewV1['localHealth'] =
        health.result === 'ok' && health.live && health.ready
            ? 'ready' : 'not_ready';
    if (!diagnostic || diagnostic.kind !== 'observational_only') {
        return unavailable(observedAt, 'LOCAL_DIAGNOSTICS_UNAVAILABLE',
            'observed', localHealth);
    }
    // Contradictory observer evidence must not become a healthy UI badge.
    if (diagnostic.localHealth !== localHealth ||
        (diagnostic.mcpInitializeObserved !== true &&
            diagnostic.toolDiscovery === 'observed_complete')) {
        return unavailable(observedAt, 'LOCAL_EVIDENCE_CONFLICT',
            'observed', 'unverified');
    }
    const validControlPlane = [
        'none', 'credential_rejected', 'permission_denied', 'rate_limited',
        'server_error', 'other_http_error', 'unverified',
    ] as const;
    let controlPlane: TunnelOperatorOverviewV1['controlPlane'] =
        validControlPlane.includes(diagnostic.controlPlaneProblem)
            ? diagnostic.controlPlaneProblem : 'unverified';
    if (!health.controlPlanePoll && controlPlane === 'none') {
        controlPlane = 'unverified';
    }
    const mcpInitialize = diagnostic.mcpInitializeObserved === true
        ? 'observed' : diagnostic.mcpInitializeObserved === false
            ? 'not_observed' : 'unverified';
    const toolDiscovery = ['observed_complete', 'observed_incomplete']
        .includes(diagnostic.toolDiscovery) ? diagnostic.toolDiscovery : 'unverified';
    const verdict = assessLocalTunnelOperability({
        localHealth,
        mcpInitializeObserved: mcpInitialize === 'observed' ? true : null,
        toolDiscovery,
        controlPlaneProblem: controlPlane,
    });
    return {
        kind: 'tunnel_operator_overview_v1', platform: 'win32',
        capabilities: 'read_only', observedAt, taskRegistration: 'observed',
        localHealth, mcpInitialize, toolDiscovery,
        controlPlane, remoteDelivery: 'not_observed',
        verdict: { state: verdict.state, reasonCode: verdict.reasonCode },
    };
}
