import { assessLocalTunnelOperability, type TunnelLocalReasonCode } from '../tunnel-local-operability.js';
import type { TunnelFunctionalDiagnostics } from '../tunnel-functional-diagnostics.js';
import type { LinuxTunnelStatus } from './tunnel-lifecycle.js';

/** Linux-only, versioned observation. Not a local operator authorization grant. */
export interface LinuxTunnelOperatorOverviewV1 {
  kind: 'tunnel_operator_linux_overview_v1';
  platform: 'linux';
  capabilities: 'read_only';
  observedAt: string;
  serviceRegistration: 'observed' | 'unverified';
  localHealth: 'ready' | 'not_ready' | 'unverified';
  mcpInitialize: 'observed' | 'not_observed' | 'unverified';
  toolDiscovery: 'observed_complete' | 'observed_incomplete' | 'unverified';
  controlPlane: TunnelFunctionalDiagnostics['controlPlaneProblem'];
  remoteDelivery: 'not_observed';
  verdict: { state: 'degraded' | 'unverified'; reasonCode:
    TunnelLocalReasonCode | 'SERVICE_STATUS_UNAVAILABLE' | 'SERVICE_INACTIVE' |
    'SERVICE_NOT_ENABLED' | 'LOCAL_DIAGNOSTICS_UNAVAILABLE' | 'LOCAL_EVIDENCE_CONFLICT' };
}

type LocalFailure = Exclude<LinuxTunnelOperatorOverviewV1['verdict']['reasonCode'], TunnelLocalReasonCode>;

function unavailable(observedAt: string, reasonCode: LocalFailure,
    serviceRegistration: LinuxTunnelOperatorOverviewV1['serviceRegistration'],
    state: LinuxTunnelOperatorOverviewV1['verdict']['state'] = 'unverified',
    localHealth: LinuxTunnelOperatorOverviewV1['localHealth'] = 'unverified',
): LinuxTunnelOperatorOverviewV1 {
  return {
    kind: 'tunnel_operator_linux_overview_v1', platform: 'linux',
    capabilities: 'read_only', observedAt, serviceRegistration, localHealth,
    mcpInitialize: 'unverified', toolDiscovery: 'unverified',
    controlPlane: 'unverified', remoteDelivery: 'not_observed',
    verdict: { state, reasonCode },
  };
}

/** Never pass through unit content, URLs, key references or provider messages. */
export function projectLinuxOperatorOverview(
    status: LinuxTunnelStatus | null,
    diagnostic: TunnelFunctionalDiagnostics | null,
    now: Date = new Date(),
): LinuxTunnelOperatorOverviewV1 {
  const observedAt = now.toISOString();
  if (!status) return unavailable(observedAt, 'SERVICE_STATUS_UNAVAILABLE', 'unverified');
  if (typeof status.active !== 'boolean' || typeof status.enabled !== 'boolean' ||
      typeof status.healthy !== 'boolean' || typeof status.controlPlanePoll !== 'boolean' ||
      (!status.active && (status.healthy || status.controlPlanePoll)) ||
      (status.healthy && !status.controlPlanePoll)) {
    return unavailable(observedAt, 'LOCAL_EVIDENCE_CONFLICT', 'unverified');
  }
  if (!status.active) {
    return unavailable(observedAt, 'SERVICE_INACTIVE', 'observed', 'degraded', 'not_ready');
  }
  if (!status.enabled) return unavailable(observedAt, 'SERVICE_NOT_ENABLED', 'observed');
  if (!diagnostic || diagnostic.kind !== 'observational_only') {
    return unavailable(observedAt, 'LOCAL_DIAGNOSTICS_UNAVAILABLE', 'observed');
  }
  const allowedHealth = ['ready', 'not_ready', 'unverified'];
  const allowedTools = ['observed_complete', 'observed_incomplete', 'unverified'];
  const allowedPlane = ['none', 'credential_rejected', 'permission_denied',
    'rate_limited', 'server_error', 'other_http_error', 'unverified'];
  if (!allowedHealth.includes(diagnostic.localHealth) ||
      !allowedTools.includes(diagnostic.toolDiscovery) ||
      !allowedPlane.includes(diagnostic.controlPlaneProblem) ||
      ![true, false, null].includes(diagnostic.mcpInitializeObserved) ||
      (status.healthy && diagnostic.localHealth !== 'ready') ||
      (status.controlPlanePoll && !status.healthy &&
       diagnostic.localHealth === 'ready' && diagnostic.controlPlaneProblem === 'none') ||
      (diagnostic.toolDiscovery === 'observed_complete' &&
       diagnostic.mcpInitializeObserved !== true)) {
    return unavailable(observedAt, 'LOCAL_EVIDENCE_CONFLICT', 'observed');
  }
  const controlPlane = !status.controlPlanePoll && diagnostic.controlPlaneProblem === 'none'
    ? 'unverified' : diagnostic.controlPlaneProblem;
  const mcpInitialize = diagnostic.mcpInitializeObserved === true
    ? 'observed' : diagnostic.mcpInitializeObserved === false
      ? 'not_observed' : 'unverified';
  const verdict = assessLocalTunnelOperability({
    localHealth: diagnostic.localHealth,
    mcpInitializeObserved: diagnostic.mcpInitializeObserved,
    toolDiscovery: diagnostic.toolDiscovery,
    controlPlaneProblem: controlPlane,
  });
  return {
    kind: 'tunnel_operator_linux_overview_v1', platform: 'linux',
    capabilities: 'read_only', observedAt, serviceRegistration: 'observed',
    localHealth: diagnostic.localHealth, mcpInitialize,
    toolDiscovery: diagnostic.toolDiscovery, controlPlane,
    remoteDelivery: 'not_observed',
    verdict: { state: verdict.state, reasonCode: verdict.reasonCode },
  };
}
