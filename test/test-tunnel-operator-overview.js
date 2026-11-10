import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runWindowsTunnelCommand, formatWindowsTunnelCommandResult } from '../dist/npm-scripts/tunnel.js';

const status = {
  taskName: 'Desktop Commander Windows Tunnel',
  task: { registered: true, executable: 'C:\\Private\\client.exe',
    profileDir: 'C:\\Private\\profiles', profileName: 'test' },
  profile: { path: 'C:\\Private\\API_KEY_NEVER_DISPLAY.yaml',
    healthUrlFile: 'C:\\Private\\health.url' },
  health: { result: 'ok', baseUrl: 'http://127.0.0.1:53844',
    live: true, ready: true, controlPlanePoll: true },
};
const diagnostics = {
  kind: 'observational_only', localHealth: 'ready',
  mcpInitializeObserved: true, toolDiscovery: 'observed_complete',
  controlPlaneProblem: 'credential_rejected',
  controlPlaneHttpStatus: 401, operatorGuidance: 'API_KEY_NEVER_DISPLAY',
  operability: { state: 'degraded', reasonCode: 'CONTROL_PLANE_CREDENTIAL_REJECTED' },
};
function dependencies(overrides = {}) {
  return { platform: 'win32',
    statusTunnel: async () => status,
    diagnoseLocal: async () => diagnostics,
    startTask: async () => { throw new Error('MUTATION_FORBIDDEN'); },
    stopTask: async () => { throw new Error('MUTATION_FORBIDDEN'); },
    installTask: async () => { throw new Error('MUTATION_FORBIDDEN'); },
    ...overrides };
}

test('operator overview distinguishes 401 from expiry and redacts private source', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies());
  assert.equal(result.action, 'overview');
  assert.equal(result.overview.kind, 'tunnel_operator_overview_v1');
  assert.equal(result.overview.controlPlane, 'credential_rejected');
  assert.equal(result.overview.verdict.state, 'degraded');
  assert.equal(result.overview.verdict.reasonCode, 'CONTROL_PLANE_CREDENTIAL_REJECTED');
  assert.equal(result.overview.remoteDelivery, 'not_observed');
  assert.equal(result.overview.capabilities, 'read_only');
  assert.equal(result.overview.taskRegistration, 'observed');
  const json = formatWindowsTunnelCommandResult(result);
  for (const forbidden of ['Private', 'API_KEY_NEVER_DISPLAY',
    '53844', 'profiles', 'expires', 'api_key', 'MUTATION_FORBIDDEN']) {
    assert.doesNotMatch(json, new RegExp(forbidden, 'i'));
  }
  assert.match(result.overview.observedAt, /^\d{4}-\d\d-\d\dT/);
});

test('healthy local evidence is NEVER claimed as remote ChatGPT delivery', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    diagnoseLocal: async () => ({ ...diagnostics, controlPlaneProblem: 'none',
      controlPlaneHttpStatus: null, operatorGuidance: null,
      operability: { state: 'healthy', reasonCode: 'SUCCESS' } }),
  }));
  assert.equal(result.overview.verdict.state, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'REMOTE_ROUND_TRIP_UNVERIFIED');
  assert.equal(result.overview.remoteDelivery, 'not_observed');
});
test('unavailable task state never leaks OS error text or pretends healthy', async () => {
  let probed = false;
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    statusTunnel: async () => { throw new Error('PRIVATE_TOKEN_LEAK'); },
    diagnoseLocal: async () => { probed = true; return diagnostics; },
  }));
  assert.equal(probed, false);
  assert.equal(result.overview.taskRegistration, 'unverified');
  assert.equal(result.overview.verdict.state, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'TASK_STATUS_UNAVAILABLE');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_TOKEN_LEAK/);
});

test('status poll conflicts with diagnostics and remains unverified', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    statusTunnel: async () => ({ ...status,
      health: { ...status.health, controlPlanePoll: false } }),
    diagnoseLocal: async () => ({ ...diagnostics,
      controlPlaneProblem: 'none', controlPlaneHttpStatus: null }),
  }));
  assert.equal(result.overview.verdict.state, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'CONTROL_PLANE_UNVERIFIED');
});
test('diagnostic failure exposes fixed reason and not sensitive error', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    diagnoseLocal: async () => { throw new Error('secret=PRIVATE_TOKEN_LEAK'); },
  }));
  assert.equal(result.overview.verdict.reasonCode, 'LOCAL_DIAGNOSTICS_UNAVAILABLE');
  assert.equal(result.overview.verdict.state, 'unverified');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_TOKEN_LEAK/);
});

test('operator overview rejects extraneous options before any OS request', async () => {
  let contacted = false;
  await assert.rejects(runWindowsTunnelCommand(['overview', '--force'], dependencies({
    statusTunnel: async () => { contacted = true; return status; },
  })), /does not accept additional arguments/i);
  assert.equal(contacted, false);
});

test('disagreeing local probes never display ready as verified', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    diagnoseLocal: async () => ({ ...diagnostics,
      localHealth: 'not_ready', controlPlaneProblem: 'none' }),
  }));
  assert.equal(result.overview.localHealth, 'unverified');
  assert.equal(result.overview.verdict.state, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'LOCAL_EVIDENCE_CONFLICT');
});

test('impossible MCP tool discovery without handshake fails closed', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    diagnoseLocal: async () => ({ ...diagnostics,
      localHealth: 'ready', mcpInitializeObserved: false,
      toolDiscovery: 'observed_complete', controlPlaneProblem: 'none' }),
  }));
  assert.equal(result.overview.toolDiscovery, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'LOCAL_EVIDENCE_CONFLICT');
});

test('tool discovery without positive initialize proof stays unverified', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    diagnoseLocal: async () => ({ ...diagnostics,
      mcpInitializeObserved: null, toolDiscovery: 'observed_complete',
      controlPlaneProblem: 'none' }),
  }));
  assert.equal(result.overview.verdict.reasonCode, 'LOCAL_EVIDENCE_CONFLICT');
  assert.equal(result.overview.toolDiscovery, 'unverified');
});

test('task-only overview remains useful without executing an unverified client', async () => {
  let observations = 0;
  let diagnosticInvocations = 0;
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    statusTunnel: async () => {
      throw new Error('Client executable is not independently verified');
    },
    observeTask: async () => {
      observations += 1;
      return { kind: 'untrusted_task_registration_v1',
        registration: { executable: 'C:\\PRIVATE_UNTRUSTED.exe',
          profileDir: 'C:\\PRIVATE', profileName: 'profile' } };
    },
    diagnoseLocal: async () => { diagnosticInvocations++; throw new Error('UNSAFE'); },
  }));
  assert.equal(observations, 1);
  assert.equal(diagnosticInvocations, 0);
  assert.equal(result.overview.taskRegistration, 'observed');
  assert.equal(result.overview.localHealth, 'unverified');
  assert.equal(result.overview.verdict.reasonCode, 'CLIENT_PROVENANCE_UNVERIFIED');
  assert.equal(result.overview.remoteDelivery, 'not_observed');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|UNSAFE/);
});

test('observed Windows task with unverified client reports provenance, not missing task', async () => {
  const result = await runWindowsTunnelCommand(['overview'], dependencies({
    statusTunnel: async () => { throw new Error('CLIENT_NOT_AUTHENTICATED'); },
    observeTask: async () => ({
      kind: 'untrusted_task_registration_v1',
      registration: {
        executable: 'C:\\PRIVATE\\unknown.exe',
        profileDir: 'C:\\PRIVATE\\profiles',
        profileName: 'private',
      },
    }),
  }));
  assert.equal(result.overview.taskRegistration, 'observed');
  assert.equal(result.overview.localHealth, 'unverified');
  assert.equal(result.overview.mcpInitialize, 'unverified');
  assert.equal(result.overview.remoteDelivery, 'not_observed');
  assert.deepEqual(result.overview.verdict, {
    state: 'unverified',
    reasonCode: 'CLIENT_PROVENANCE_UNVERIFIED',
  });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|CLIENT_NOT_AUTHENTICATED/);
});
