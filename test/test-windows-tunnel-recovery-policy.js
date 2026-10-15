import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decideTunnelRecovery } from '../dist/platform/windows/tunnel-recovery-policy.js';

const base = Object.freeze({
  desired: 'running',
  process: 'absent',
  health: 'unknown',
  network: 'online',
  nowMs: 10_000,
  attempts: 0,
  lastAttemptMs: null,
});
const limits = Object.freeze({ maxAttempts: 3, baseDelayMs: 1000, maxDelayMs: 5000 });
const decide = (patch = {}, policy = limits) => decideTunnelRecovery({ ...base, ...patch }, policy);
const reason = (patch) => decide(patch).reason;

test('candidate requires explicit running intent, a known absent tunnel and online network', () => {
  assert.deepEqual(decide(), { kind: 'start_candidate', reason: 'missing_tunnel' });
  assert.equal(reason({ desired: 'stopped' }), 'intentional_stop');
  assert.equal(reason({ desired: 'unknown' }), 'unknown_desired_state');
  assert.equal(reason({ process: 'unknown' }), 'unknown_process_state');
  assert.equal(reason({ network: 'unknown' }), 'unknown_network');
  assert.equal(reason({ network: 'offline' }), 'network_offline');
});

test('a deliberate stop is never reversed, even when observations conflict', () => {
  assert.deepEqual(decide({ desired: 'stopped', process: 'running' }), {
    kind: 'operator_required', reason: 'running_while_stopped',
  });
  assert.equal(reason({ desired: 'stopped', process: 'unknown' }), 'intentional_stop');
});

test('running tunnel is never restarted by a pure decision', () => {
  assert.deepEqual(decide({ process: 'running', health: 'healthy' }), {
    kind: 'healthy', reason: 'healthy',
  });
  assert.deepEqual(decide({ process: 'running', health: 'degraded' }), {
    kind: 'operator_required', reason: 'degraded_running_tunnel',
  });
  assert.equal(reason({ process: 'running', health: 'unknown' }), 'unknown_health');
  assert.equal(reason({ process: 'absent', health: 'healthy' }), 'inconsistent_observation');
});

test('retries are bounded, delayed and do not spin after exhaustion', () => {
  assert.deepEqual(decide({ attempts: 1, lastAttemptMs: 9500 }), {
    kind: 'hold', reason: 'backoff', retryAfterMs: 500,
  });
  assert.equal(decide({ attempts: 1, lastAttemptMs: 9000 }).kind, 'start_candidate');
  assert.deepEqual(decide({ attempts: 2, lastAttemptMs: 9000 }), {
    kind: 'hold', reason: 'backoff', retryAfterMs: 1000,
  });
  assert.equal(decide({ attempts: 2, lastAttemptMs: 8000 }).kind, 'start_candidate');
  assert.deepEqual(decide({ attempts: 3, lastAttemptMs: 0 }), {
    kind: 'operator_required', reason: 'retry_budget_exhausted',
  });
  assert.equal(reason({ attempts: 0, lastAttemptMs: 9000 }), 'inconsistent_attempt_history');
  assert.equal(reason({ attempts: 1, lastAttemptMs: null }), 'inconsistent_attempt_history');
  assert.equal(reason({ attempts: 1, lastAttemptMs: 10001 }), 'clock_regression');
});

test('exponential backoff honors a configurable upper bound', () => {
  assert.deepEqual(decide({ attempts: 5, lastAttemptMs: 9000 }, {
    maxAttempts: 8, baseDelayMs: 1000, maxDelayMs: 5000,
  }), { kind: 'hold', reason: 'backoff', retryAfterMs: 4000 });
  assert.deepEqual(decide({ attempts: 5, lastAttemptMs: 5000 }, {
    maxAttempts: 8, baseDelayMs: 1000, maxDelayMs: 5000,
  }), { kind: 'start_candidate', reason: 'missing_tunnel' });
  assert.equal(decide({}, { ...limits, maxAttempts: 0 }).reason, 'retry_budget_exhausted');
});

test('malformed and unsafe observations fail closed before making a decision', () => {
  for (const [key, value] of [
    ['desired', 'enabled'],
    ['process', 'stopped'],
    ['health', true],
    ['network', 'unreachable'],
    ['nowMs', Number.NaN],
    ['nowMs', Number.POSITIVE_INFINITY],
    ['attempts', -1],
    ['attempts', 33],
    ['attempts', 1.5],
    ['lastAttemptMs', undefined],
    ['lastAttemptMs', -1],
    ['lastAttemptMs', Number.MAX_SAFE_INTEGER + 1],
  ]) {
    assert.throws(() => decide({ [key]: value }), Error, key);
  }
  for (const invalid of [
    { maxAttempts: -1 },
    { maxAttempts: 33 },
    { baseDelayMs: 999 },
    { baseDelayMs: 1000.1 },
    { baseDelayMs: 3600001 },
    { maxDelayMs: 999 },
    { maxDelayMs: 86400001 },
  ]) {
    assert.throws(() => decide({}, { ...limits, ...invalid }), Error);
  }
  assert.throws(() => decideTunnelRecovery(null, limits), Error);
  assert.throws(() => decideTunnelRecovery(base, null), Error);
});

test('policy is deterministic and never modifies the observation or limits', () => {
  const sample = Object.freeze({ ...base, attempts: 1, lastAttemptMs: 9000 });
  const first = decideTunnelRecovery(sample, limits);
  assert.deepEqual(decideTunnelRecovery(sample, limits), first);
  assert.deepEqual(sample, { ...base, attempts: 1, lastAttemptMs: 9000 });
  assert.deepEqual(limits, { maxAttempts: 3, baseDelayMs: 1000, maxDelayMs: 5000 });
});
