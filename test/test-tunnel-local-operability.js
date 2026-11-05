import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseTunnelFunctionalHealth } from '../dist/platform/windows/tunnel-functional-diagnostics.js';

function observation(status = 'ok', code = null) {
  return {
    live: true, ready: true,
    components: {
      mcp: { details: {
        initialize: { ok: true },
        tools_list: { ok: true, complete: true },
      } },
      dispatcher: { details: { active: 0, failures: 0, timeouts: 0 } },
      queue: { details: { depth: 0 } },
      'control-plane': {
        status,
        reason_code: status === 'degraded' ? 'http_error' : null,
        details: { consecutive_failures: status === 'degraded' ? 3 : 0,
          ...(code === null ? {} : { http_status: code }) },
      },
    },
  };
}

test('ready process and HTTP 401 remain degraded, never remotely healthy', () => {
  const health = observation('degraded', 401);
  health.components.mcp.details.initialize.ok = false;
  health.components.mcp.details.tools_list.complete = false;
  health.components['control-plane'].details.last_error = 'SENSITIVE_BEARER_MUST_NOT_LEAK';
  const result = parseTunnelFunctionalHealth(health);
  assert.deepEqual(result.operability, {
    kind: 'local_operability_v1', state: 'degraded',
    reasonCode: 'CONTROL_PLANE_CREDENTIAL_REJECTED',
    remoteRoundTrip: 'not_observed',
  });
  assert.doesNotMatch(JSON.stringify(result), /SENSITIVE_BEARER_MUST_NOT_LEAK/);
});

test('observed control-plane errors have stable non-secret reason codes', () => {
  for (const [code, reasonCode] of [
    [403, 'CONTROL_PLANE_FORBIDDEN'],
    [429, 'CONTROL_PLANE_RATE_LIMITED'],
    [500, 'CONTROL_PLANE_SERVER_ERROR'],
    [418, 'CONTROL_PLANE_HTTP_ERROR'],
  ]) {
    const result = parseTunnelFunctionalHealth(observation('degraded', code));
    assert.equal(result.operability.state, 'degraded');
    assert.equal(result.operability.reasonCode, reasonCode);
  }
});

test('all green local observations cannot prove fresh remote MCP delivery', () => {
  const result = parseTunnelFunctionalHealth(observation());
  assert.deepEqual(result.operability, {
    kind: 'local_operability_v1', state: 'unverified',
    reasonCode: 'REMOTE_ROUND_TRIP_UNVERIFIED',
    remoteRoundTrip: 'not_observed',
  });
});

test('missing handshake evidence is unknown, not authenticated or healthy', () => {
  const data = observation();
  delete data.components.mcp.details.initialize;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.operability.state, 'unverified');
  assert.equal(result.operability.reasonCode, 'MCP_HANDSHAKE_UNOBSERVED');
});

test('local not-ready has actionable cause but no invented remote evidence', () => {
  const data = observation();
  data.ready = false;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.operability.state, 'degraded');
  assert.equal(result.operability.reasonCode, 'LOCAL_NOT_READY');
  assert.equal(result.operability.remoteRoundTrip, 'not_observed');
});

test('incomplete MCP discovery remains unverified', () => {
  const data = observation();
  data.components.mcp.details.tools_list.complete = false;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.operability.state, 'unverified');
  assert.equal(result.operability.reasonCode, 'MCP_TOOLS_LIST_UNVERIFIED');
});

test('unclassified control plane cannot be rendered healthy', () => {
  const data = observation('degraded', 0);
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.operability.state, 'unverified');
  assert.equal(result.operability.reasonCode, 'CONTROL_PLANE_UNVERIFIED');
});

test('absent health flags remain unverified, not a claimed outage', () => {
  const data = observation();
  delete data.live;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.localHealth, 'unverified');
  assert.equal(result.operability.state, 'unverified');
  assert.equal(result.operability.reasonCode, 'LOCAL_READINESS_UNVERIFIED');
});

test('stale 401 with zero consecutive failures is not a fresh credential denial', () => {
  const data = observation('degraded', 401);
  data.components['control-plane'].details.consecutive_failures = 0;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.controlPlaneHttpStatus, null);
  assert.equal(result.controlPlaneProblem, 'unverified');
  assert.equal(result.operability.reasonCode, 'CONTROL_PLANE_UNVERIFIED');
});

test('missing failure counter cannot turn an old HTTP 401 into an active denial', () => {
  const data = observation('degraded', 401);
  delete data.components['control-plane'].details.consecutive_failures;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.controlPlaneHttpStatus, null);
  assert.equal(result.operability.state, 'unverified');
  assert.equal(result.operability.reasonCode, 'CONTROL_PLANE_UNVERIFIED');
});

test('unknown control-plane status cannot mask a confirmed local readiness failure', () => {
  const data = observation('degraded', 0);
  data.ready = false;
  const result = parseTunnelFunctionalHealth(data);
  assert.equal(result.localHealth, 'not_ready');
  assert.equal(result.operability.state, 'degraded');
  assert.equal(result.operability.reasonCode, 'LOCAL_NOT_READY');
});
