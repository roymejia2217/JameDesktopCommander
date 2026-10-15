import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  evaluateRecoveryFencing,
} from '../dist/platform/windows/tunnel-recovery-fencing.js';

const controller = randomUUID();
const replacement = randomUUID();
const fingerprint = 'a'.repeat(64);
const otherFingerprint = 'b'.repeat(64);
const request = Object.freeze({
  controllerId: controller,
  controllerEpoch: 9,
  expectedStateRevision: 3,
  expectedTaskDigest: fingerprint,
  nowMs: 10000,
});
const state = Object.freeze({
  schemaVersion: 1,
  revision: 3,
  desired: 'running',
  retryAttempts: 0,
  lastAttemptMs: null,
});
const evidence = Object.freeze({
  state,
  lease: Object.freeze({
    ownerId: controller, epoch: 9, status: 'held', expiresAtMs: 15000,
  }),
  task: Object.freeze({ digest: fingerprint, identityVerified: true }),
  process: 'absent',
  health: 'unknown',
  network: 'online',
});
const limits = Object.freeze({ maxAttempts: 3, baseDelayMs: 1000, maxDelayMs: 8000 });
const decide = (req = {}, proof = {}) => evaluateRecoveryFencing(
  { ...request, ...req },
  { ...evidence, ...proof },
  limits,
);

test('fresh, consistent evidence is only an eligible candidate, not an action', () => {
  assert.deepEqual(decide(), { kind: 'eligible', reason: 'fenced_candidate' });
});

test('a changed durable revision invalidates the candidate', () => {
  assert.equal(decide({}, { state: { ...state, revision: 4 } }).reason, 'revision_changed');
  assert.equal(decide({ expectedStateRevision: 2 }).reason, 'revision_changed');
});

test('released, unknown, expired and wrong-owner leases always hold', () => {
  for (const status of ['released', 'unknown']) {
    assert.equal(decide({}, { lease: { ...evidence.lease, status } }).reason, 'lease_unavailable');
  }
  assert.equal(decide({}, { lease: { ...evidence.lease, ownerId: replacement } }).reason, 'lease_owner_changed');
  assert.equal(decide({}, { lease: { ...evidence.lease, epoch: 10 } }).reason, 'lease_epoch_changed');
  assert.equal(decide({ controllerEpoch: 8 }).reason, 'lease_epoch_changed');
  assert.equal(decide({ nowMs: 15000 }).reason, 'lease_expired');
  assert.equal(decide({ nowMs: 15001 }).reason, 'lease_expired');
});

test('identity verification and exact executable/task fingerprint are required', () => {
  assert.equal(decide({}, {
    task: { ...evidence.task, identityVerified: false },
  }).reason, 'task_identity_unverified');
  assert.equal(decide({}, {
    task: { ...evidence.task, digest: otherFingerprint },
  }).reason, 'task_identity_changed');
  assert.equal(decide({ expectedTaskDigest: otherFingerprint }).reason, 'task_identity_changed');
});

test('intent changes and uncertain or degraded observations fail closed', () => {
  for (const [proof, reason] of [
    [{ state: { ...state, desired: 'stopped' } }, 'intentional_stop'],
    [{ process: 'running', health: 'healthy' }, 'healthy'],
    [{ process: 'running', health: 'degraded' }, 'degraded_running_tunnel'],
    [{ process: 'unknown' }, 'unknown_process_state'],
    [{ network: 'offline' }, 'network_offline'],
    [{ network: 'unknown' }, 'unknown_network'],
    [{ health: 'healthy' }, 'inconsistent_observation'],
  ]) {
    assert.deepEqual(decide({}, proof), {
      kind: 'hold', reason: 'policy_rejected', policyReason: reason,
    });
  }
});

test('retry budgets, backoff and invalid durable history remain authoritative', () => {
  const past = { ...state, retryAttempts: 2, lastAttemptMs: 9500 };
  assert.equal(decide({}, { state: past }).policyReason, 'backoff');
  assert.equal(decide({}, { state: { ...state, retryAttempts: 3, lastAttemptMs: 1000 } }).policyReason, 'retry_budget_exhausted');
  assert.throws(() => decide({}, {
    state: { ...state, retryAttempts: 1, lastAttemptMs: null },
  }), /inconsistent/i);
});

test('malformed or missing authority evidence never grants eligibility', () => {
  for (const [req, proof] of [
    [{ controllerId: 'forged' }, {}],
    [{ controllerEpoch: 0 }, {}],
    [{ expectedStateRevision: -1 }, {}],
    [{ nowMs: Number.NaN }, {}],
    [{ expectedTaskDigest: 'not-a-sha256' }, {}],
    [{}, { lease: { ...evidence.lease, ownerId: 'bad' } }],
    [{}, { lease: { ...evidence.lease, epoch: 0 } }],
    [{}, { lease: { ...evidence.lease, expiresAtMs: -1 } }],
    [{}, { lease: { ...evidence.lease, status: 'lost' } }],
    [{}, { task: { ...evidence.task, identityVerified: 'yes' } }],
    [{}, { task: { ...evidence.task, digest: 'invalid' } }],
    [{}, { state: { ...state, unknown: 'allowed' } }],
  ]) {
    assert.throws(() => decide(req, proof), Error);
  }
  assert.throws(() => evaluateRecoveryFencing(null, evidence, limits), Error);
  assert.throws(() => evaluateRecoveryFencing(request, null, limits), Error);
});

test('evaluations are repeatable and do not change the supplied snapshots', () => {
  const before = JSON.stringify({ request, evidence, limits });
  assert.deepEqual(decide(), decide());
  assert.equal(JSON.stringify({ request, evidence, limits }), before);
});
