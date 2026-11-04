import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assessTunnelLocalLifecycle } from '../dist/platform/tunnel-local-operability.js';

const snapshot = (extra = {}) => ({
  active: true, enabled: true, healthy: true, controlPlanePoll: true, ...extra,
});
const expected = (state, reasonCode) => ({
  kind: 'local_lifecycle_only', state, reasonCode,
  remoteRoundTrip: 'not_observed',
});

test('all locally green Linux probes cannot claim remote MCP round trip', () => {
  assert.deepEqual(assessTunnelLocalLifecycle(snapshot()),
    expected('unverified', 'REMOTE_ROUND_TRIP_UNVERIFIED'));
});

test('inactive service is observed without inventing operator intent', () => {
  for (const enabled of [true, false]) {
    assert.deepEqual(assessTunnelLocalLifecycle(snapshot({
      active: false, enabled, healthy: false, controlPlanePoll: false,
    })), expected('inactive', 'SERVICE_INACTIVE'));
  }
});

test('running unit disabled in manager is not treated as a remotely healthy service', () => {
  const out = assessTunnelLocalLifecycle(snapshot({ enabled: false }));
  assert.deepEqual(out, expected('unverified', 'SERVICE_NOT_ENABLED'));
});

test('absent control-plane polling remains unknown, not evidence of expired keys', () => {
  const out = assessTunnelLocalLifecycle(snapshot({ healthy: false, controlPlanePoll: false }));
  assert.deepEqual(out, expected('unverified', 'CONTROL_PLANE_POLL_UNVERIFIED'));
  assert.doesNotMatch(JSON.stringify(out), /expired|credential_rejected/i);
});

test('poll success cannot mask missing aggregated local health', () => {
  const out = assessTunnelLocalLifecycle(snapshot({ healthy: false }));
  assert.deepEqual(out, expected('unverified', 'LOCAL_HEALTH_UNVERIFIED'));
});

test('contradictory local evidence is explicitly unknown', () => {
  for (const data of [
    snapshot({ active: false }),
    snapshot({ healthy: true, controlPlanePoll: false }),
  ]) {
    const out = assessTunnelLocalLifecycle(data);
    assert.deepEqual(out, expected('unverified', 'LOCAL_EVIDENCE_CONFLICT'));
  }
});

test('malformed or injected state never elevates a health claim or echoes secrets', () => {
  for (const patch of [
    { active: 'true' }, { enabled: 1 }, { healthy: null },
    { controlPlanePoll: undefined },
  ]) {
    assert.deepEqual(assessTunnelLocalLifecycle(snapshot(patch)),
      expected('unverified', 'LOCAL_EVIDENCE_CONFLICT'));
  }
  const withSecret = { ...snapshot(), bearer: 'PRIVATE_KEY_MUST_NOT_LEAK' };
  const out = assessTunnelLocalLifecycle(withSecret);
  assert.doesNotMatch(JSON.stringify(out), /PRIVATE_KEY_MUST_NOT_LEAK|bearer/);
  assert.deepEqual(out, expected('unverified', 'REMOTE_ROUND_TRIP_UNVERIFIED'));
});
