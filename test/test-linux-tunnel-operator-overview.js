import assert from 'node:assert/strict';
import { test } from 'node:test';
import { projectLinuxOperatorOverview } from '../dist/platform/linux/tunnel-operator-overview.js';
import { runLinuxTunnelCommand } from '../dist/platform/linux/tunnel-lifecycle.js';

const status = {
  unit: 'jame-desktop-commander-tunnel.service',
  active: true, enabled: true, healthy: true, controlPlanePoll: true,
  credentialSource: 'file_reference',
};
const diagnostics = {
  kind: 'observational_only',
  localHealth: 'ready', mcpInitializeObserved: true,
  toolDiscovery: 'observed_complete',
  controlPlaneProblem: 'credential_rejected',
  controlPlaneHttpStatus: 401,
  operatorGuidance: 'secret=SHOULD_NOT_APPEAR',
};
const now = new Date('2026-11-06T20:00:00.000Z');

test('Linux operator observes a rejected credential, never its expiry or a remote connection', () => {
  const overview = projectLinuxOperatorOverview(status, diagnostics, now);
  assert.equal(overview.kind, 'tunnel_operator_linux_overview_v1');
  assert.equal(overview.platform, 'linux');
  assert.equal(overview.capabilities, 'read_only');
  assert.equal(overview.serviceRegistration, 'observed');
  assert.equal(overview.verdict.state, 'degraded');
  assert.equal(overview.verdict.reasonCode, 'CONTROL_PLANE_CREDENTIAL_REJECTED');
  assert.equal(overview.remoteDelivery, 'not_observed');
  assert.equal(overview.observedAt, now.toISOString());
  const serialized = JSON.stringify(overview);
  assert.doesNotMatch(serialized, /SHOULD_NOT_APPEAR|file_reference|expired|api_key/i);
});

test('local success without a remote witness is unverified', () => {
  const view = projectLinuxOperatorOverview(status, {
    ...diagnostics, controlPlaneProblem: 'none',
  }, now);
  assert.equal(view.verdict.state, 'unverified');
  assert.equal(view.verdict.reasonCode, 'REMOTE_ROUND_TRIP_UNVERIFIED');
  assert.equal(view.remoteDelivery, 'not_observed');
});

test('inactive or disabled systemd service cannot claim readiness', () => {
  const inactive = projectLinuxOperatorOverview({
    ...status, active: false, healthy: false, controlPlanePoll: false,
  }, diagnostics, now);
  assert.equal(inactive.verdict.reasonCode, 'SERVICE_INACTIVE');
  assert.equal(inactive.localHealth, 'not_ready');
  assert.equal(inactive.mcpInitialize, 'unverified');
  const disabled = projectLinuxOperatorOverview({
    ...status, enabled: false,
  }, diagnostics, now);
  assert.equal(disabled.verdict.reasonCode, 'SERVICE_NOT_ENABLED');
  assert.equal(disabled.verdict.state, 'unverified');
});

test('unavailable Linux probes and contradictory MCP data fail closed', () => {
  const missing = projectLinuxOperatorOverview(null, diagnostics, now);
  assert.equal(missing.serviceRegistration, 'unverified');
  assert.equal(missing.verdict.reasonCode, 'SERVICE_STATUS_UNAVAILABLE');
  assert.equal(missing.localHealth, 'unverified');
  const diagnosticMissing = projectLinuxOperatorOverview(status, null, now);
  assert.equal(diagnosticMissing.verdict.reasonCode, 'LOCAL_DIAGNOSTICS_UNAVAILABLE');
  const contradictory = projectLinuxOperatorOverview(status, {
    ...diagnostics, mcpInitializeObserved: false,
  }, now);
  assert.equal(contradictory.verdict.reasonCode, 'LOCAL_EVIDENCE_CONFLICT');
  assert.equal(contradictory.toolDiscovery, 'unverified');
});

test('missing control-plane poll cannot promote local diagnostics into successful control plane', () => {
  const overview = projectLinuxOperatorOverview({
    ...status, healthy: false, controlPlanePoll: false,
  }, { ...diagnostics, controlPlaneProblem: 'none' }, now);
  assert.equal(overview.controlPlane, 'unverified');
  assert.equal(overview.verdict.state, 'unverified');
});

test('Linux overview rejects extra options without mutating service', async () => {
  const commands = [];
  const deps = { platform: 'linux', uid: () => 1000, home: '/tmp',
    run: async (bin, args) => { commands.push([bin, ...args]); return ''; } };
  await assert.rejects(runLinuxTunnelCommand(['overview', '--force'], deps),
    /no extra arguments/i);
  assert.deepEqual(commands, [], 'Invalid overview flags must be rejected before any systemd request');
});

test('missing Linux registration yields sanitized read-only unverified response', async () => {
  const commands = [];
  const deps = { platform: 'linux', uid: () => 1000,
    home: '/path/that/is/not/an/installed/jdc/unit',
    run: async (bin, args) => {
      commands.push([bin, ...args]); throw new Error('SECRET_PRIVATE_PROVIDER_VALUE');
    } };
  const result = await runLinuxTunnelCommand(['overview'], deps);
  assert.equal(result.action, 'overview');
  assert.equal(result.overview.verdict.reasonCode, 'SERVICE_STATUS_UNAVAILABLE');
  assert.equal(result.overview.remoteDelivery, 'not_observed');
  assert.doesNotMatch(JSON.stringify(result), /SECRET_PRIVATE_PROVIDER_VALUE/);
  assert.equal(commands.some(x => /enable|disable|restart|install/.test(x.join(' '))), false);
});
