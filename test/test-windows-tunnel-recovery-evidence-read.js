import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { probeRecoveryEvidenceReadOnly } from '../dist/platform/windows/tunnel-recovery-evidence-read.js';

const id = randomUUID();
const other = randomUUID();
const digest = 'a'.repeat(64);
const state = Object.freeze({
  schemaVersion: 1, revision: 5, desired: 'running',
  retryAttempts: 0, lastAttemptMs: null,
});
const lease = Object.freeze({
  ownerId: id, epoch: 11, status: 'held', expiresAtMs: 5000,
});
const taskIdentity = Object.freeze({ digest, identityVerified: true });
const runtime = Object.freeze({ process: 'absent', health: 'unknown', network: 'online' });
const request = Object.freeze({
  controllerId: id, controllerEpoch: 11,
  expectedStateRevision: 5, expectedTaskDigest: digest,
});
const limits = Object.freeze({ maxAttempts: 3, baseDelayMs: 1000, maxDelayMs: 8000 });
function provider({
  states = [state, state], leases = [lease, lease],
  tasks = [taskIdentity, taskIdentity], runtimes = [runtime, runtime],
  times = [1000, 1200],
} = {}) {
  const count = { state: 0, lease: 0, task: 0, runtime: 0, clock: 0 };
  const take = async (key, items) => items[count[key]++];
  return {
    count,
    readState: () => take('state', states),
    readLease: () => take('lease', leases),
    readTaskIdentity: () => take('task', tasks),
    readRuntime: () => take('runtime', runtimes),
    readClockMs: () => take('clock', times),
  };
}
const probe = (reader, req = request) => probeRecoveryEvidenceReadOnly(req, limits, reader);

test('two complete stable passes return an informational candidate only', async () => {
  const reader = provider();
  assert.deepEqual(await probe(reader), {
    kind: 'candidate_only', reason: 'consistent_preflight',
  });
  assert.deepEqual(reader.count, {
    state: 2, lease: 2, task: 2, runtime: 2, clock: 2,
  });
});

test('operator stop and revision drift reject candidates', async () => {
  assert.equal((await probe(provider({
    states: [state, { ...state, desired: 'stopped' }],
  }))).reason, 'evidence_changed');
  assert.equal((await probe(provider({
    states: [state, { ...state, revision: 6 }],
  }))).reason, 'evidence_changed');
  const stopped = { ...state, desired: 'stopped' };
  assert.deepEqual(await probe(provider({ states: [stopped, stopped] })), {
    kind: 'hold', reason: 'preflight_rejected',
    preflightReason: 'policy_rejected', policyReason: 'intentional_stop',
  });
});

test('loss of lease, epoch and ownership between reads fails closed', async () => {
  for (const changed of [
    { ...lease, status: 'released' },
    { ...lease, ownerId: other },
    { ...lease, epoch: 12 },
    { ...lease, expiresAtMs: 9000 },
  ]) {
    assert.equal((await probe(provider({ leases: [lease, changed] }))).reason, 'evidence_changed');
  }
  const expired = { ...lease, expiresAtMs: 1200 };
  assert.equal((await probe(provider({ leases: [expired, expired] }))).preflightReason, 'lease_expired');
});

test('task and network changes invalidate the observation', async () => {
  assert.equal((await probe(provider({
    tasks: [taskIdentity, { digest: 'b'.repeat(64), identityVerified: true }],
  }))).reason, 'evidence_changed');
  assert.equal((await probe(provider({
    runtimes: [runtime, { ...runtime, network: 'offline' }],
  }))).reason, 'evidence_changed');
  const offline = { ...runtime, network: 'offline' };
  assert.equal((await probe(provider({ runtimes: [offline, offline] }))).policyReason, 'network_offline');
});

test('clock regression and lease expiry reject candidates', async () => {
  assert.equal((await probe(provider({ times: [1200, 1100] }))).reason, 'clock_regression');
  assert.equal((await probe(provider({ times: [1000, 5000] }))).preflightReason, 'lease_expired');
});

test('faulty sources and malformed observations are never accepted', async () => {
  const reader = provider();
  reader.readState = async () => { throw new Error('I/O failure'); };
  assert.deepEqual(await probe(reader), { kind: 'hold', reason: 'evidence_unavailable' });
  assert.deepEqual(await probe({}), { kind: 'hold', reason: 'evidence_unavailable' });
  assert.deepEqual(await probe(null), { kind: 'hold', reason: 'evidence_unavailable' });
  assert.equal((await probe(provider({ times: [NaN, 1000] }))).reason, 'evidence_unavailable');
  assert.equal((await probe(provider({
    states: [{ ...state, extra: 'forgery' }, { ...state, extra: 'forgery' }],
  }))).reason, 'evidence_unavailable');
  assert.equal((await probe(provider({
    leases: [{ ...lease, status: 'forgery' }, { ...lease, status: 'forgery' }],
  }))).reason, 'invalid_evidence');
  assert.equal((await probe(provider({
    tasks: [{ digest: 'invalid', identityVerified: true }, { digest: 'invalid', identityVerified: true }],
  }))).reason, 'invalid_evidence');
  assert.equal((await probe(provider(), { ...request, controllerId: 'forgery' })).reason, 'invalid_evidence');
});

test('bounded retry policy and uncertain health remain authoritative', async () => {
  const retries = { ...state, retryAttempts: 3, lastAttemptMs: 900 };
  assert.equal((await probe(provider({ states: [retries, retries] }))).policyReason, 'retry_budget_exhausted');
  const unknown = { ...runtime, process: 'unknown' };
  assert.equal((await probe(provider({ runtimes: [unknown, unknown] }))).policyReason, 'unknown_process_state');
});

test('input objects are unchanged after evaluation', async () => {
  const before = JSON.stringify([state, lease, taskIdentity, runtime, request, limits]);
  assert.equal((await probe(provider())).kind, 'candidate_only');
  assert.equal(JSON.stringify([state, lease, taskIdentity, runtime, request, limits]), before);
});
