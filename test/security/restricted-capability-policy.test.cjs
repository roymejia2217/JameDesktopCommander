'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const path = require('node:path');
const os = require('node:os');
const { RestrictedCapabilityPolicy } = require('./support/restricted-capability-policy.cjs');

const ROOT = path.resolve(os.tmpdir(), 'jdc-cap-policy-fixture');
const OTHER = path.resolve(os.tmpdir(), 'jdc-cap-policy-other');
const denied = { code: 'E_CAPABILITY_POLICY' };
function mockNative(state) {
  return class MockRootCapability {
    constructor(root) {
      if (state.failAt === root) throw Error('native root open failed');
      this.root = root;
      this.closed = false;
      state.created.push(this);
    }
    readBytes(relative) {
      if (this.closed) throw Error('closed');
      state.calls.push(['read', this.root, relative]);
      return Buffer.from(relative);
    }
    writeBytes(relative, bytes, mode) {
      if (this.closed) throw Error('closed');
      state.calls.push(['write', this.root, relative, bytes.toString('hex'), mode]);
    }
    close() { this.closed = true; state.closed.push(this.root); }
  };
}
function fixture() {
  const state = { created: [], closed: [], calls: [], failAt: null };
  let snapshot = { revision: 'r1', mode: 'restricted', allowedRoots: [ROOT] };
  let read = async () => snapshot;
  const policy = new RestrictedCapabilityPolicy({
    RootCapability: mockNative(state), readVerifiedPolicy: () => read(),
  });
  return { policy, state, set: x => { snapshot = x; }, setReader: x => { read = x; } };
}

test('missing/wrong native addon or untrusted policy loader cannot enable policy', () => {
  assert.throws(() => new RestrictedCapabilityPolicy(), denied);
  assert.throws(() => new RestrictedCapabilityPolicy({ readVerifiedPolicy: async () => ({}), RootCapability: class {} }), denied);
});

test('uninitialized policy denies and loading produces opaque scoped byte access', async () => {
  const { policy, state } = fixture();
  await assert.rejects(policy.readBytes(path.join(ROOT, 'a.bin')), denied);
  await policy.reload();
  assert.equal(policy.state, 'active');
  assert.deepEqual(await policy.readBytes(path.join(ROOT, 'a.bin')), Buffer.from('a.bin'));
  await policy.writeBytes(path.join(ROOT, 'a.bin'), Buffer.from([0,255]), 'rewrite');
  assert.deepEqual(state.calls[1], ['write', ROOT, 'a.bin', '00ff', 'rewrite']);
  policy.close();
});

test('rejects external absolute, parent traversal, root itself and relative user path', async () => {
  const { policy, state } = fixture();
  await policy.reload();
  for (const input of [path.join(OTHER, 'x'), path.resolve(ROOT, '..', 'outside.txt'), ROOT, 'relative.txt']) {
    await assert.rejects(policy.readBytes(input), denied);
  }
  await assert.rejects(policy.writeBytes(path.join(OTHER, 'x'), Buffer.from('bad'), 'append'), denied);
  assert.equal(state.calls.length, 0);
  policy.close();
});

test('restricts access to longest matching root without leaking handles', async () => {
  const { policy, state, set } = fixture();
  set({ mode: 'restricted', revision: 'r1', allowedRoots: [ROOT, path.join(ROOT, 'nested')] });
  await policy.reload();
  assert.deepEqual(await policy.readBytes(path.join(ROOT, 'nested', 'inside.bin')), Buffer.from('inside.bin'));
  assert.equal(state.calls[0][1], path.join(ROOT, 'nested'));
  policy.invalidate();
  assert.equal(state.closed.length, 2);
  await assert.rejects(policy.readBytes(path.join(ROOT, 'nested', 'inside.bin')), denied);
});

test('a changed policy revision immediately revokes previously opened handles', async () => {
  const { policy, state, set } = fixture();
  await policy.reload();
  set({ mode: 'restricted', revision: 'r2', allowedRoots: [OTHER] });
  await assert.rejects(policy.readBytes(path.join(ROOT, 'safe')), denied);
  assert.equal(state.created[0].closed, true);
  assert.equal(policy.state, 'revoked');
  await assert.rejects(policy.readBytes(path.join(OTHER, 'file')), denied);
  await policy.reload();
  assert.deepEqual(await policy.readBytes(path.join(OTHER, 'file')), Buffer.from('file'));
  await assert.rejects(policy.readBytes(path.join(ROOT, 'old')), denied);
  policy.close();
});

test('root changes with unchanged revision still revoke capabilities', async () => {
  const { policy, state, set } = fixture();
  await policy.reload();
  set({ mode: 'restricted', revision: 'r1', allowedRoots: [OTHER] });
  await assert.rejects(policy.writeBytes(path.join(ROOT, 'safe'), Buffer.from('bad'), 'rewrite'), denied);
  assert.equal(state.created[0].closed, true);
  assert.equal(state.calls.length, 0);
});

test('provider failure and malformed empty/unrestricted policy fail closed', async () => {
  const { policy, state, set, setReader } = fixture();
  await policy.reload();
  setReader(async () => { throw new Error('disk unavailable'); });
  await assert.rejects(policy.readBytes(path.join(ROOT, 'safe')), denied);
  assert.equal(state.created[0].closed, true);
  setReader(async () => ({ mode: 'restricted', revision: 'new', allowedRoots: [] }));
  await assert.rejects(policy.reload(), denied);
  set({ mode: 'unrestricted', revision: 'new', allowedRoots: [ROOT] });
  setReader(async () => ({ mode: 'unrestricted', revision: 'new', allowedRoots: [ROOT] }));
  await assert.rejects(policy.reload(), denied);
  assert.equal(policy.state, 'revoked');
});

test('partial native root-open failure closes earlier roots and publishes no policy', async () => {
  const { policy, state, set } = fixture();
  set({ mode: 'restricted', revision: 'r1', allowedRoots: [ROOT, OTHER] });
  state.failAt = OTHER;
  await assert.rejects(policy.reload(), denied);
  assert.equal(state.created.length, 1);
  assert.equal(state.created[0].closed, true);
  assert.equal(policy.state, 'revoked');
  assert.equal(state.calls.length, 0);
});

test('invalid input is denied before a native write call', async () => {
  const { policy, state } = fixture();
  await policy.reload();
  await assert.rejects(policy.writeBytes(path.join(ROOT, 'safe'), 'text', 'rewrite'), denied);
  await assert.rejects(policy.writeBytes(path.join(ROOT, 'safe'), Buffer.from('bad'), 'invalid'), denied);
  assert.equal(state.calls.length, 0);
  policy.close();
});

test('invalidation during pending verified-policy read denies stale result', async () => {
  const { policy, state, setReader } = fixture();
  await policy.reload();
  let resolveSnapshot;
  setReader(() => new Promise(resolve => { resolveSnapshot = resolve; }));
  const operation = policy.readBytes(path.join(ROOT, 'pending.bin'));
  policy.invalidate();
  resolveSnapshot({ mode: 'restricted', revision: 'r1', allowedRoots: [ROOT] });
  await assert.rejects(operation, denied);
  assert.equal(state.calls.length, 0);
  assert.equal(state.created[0].closed, true);
});

test('competing reloads cannot resurrect a superseded policy generation', async () => {
  const { policy, state, setReader } = fixture();
  let resolveFirst, times = 0;
  setReader(() => ++times === 1 ? new Promise(resolve => { resolveFirst = resolve; }) :
    Promise.resolve({ mode: 'restricted', revision: 'r2', allowedRoots: [OTHER] }));
  const old = policy.reload();
  await policy.reload();
  resolveFirst({ mode: 'restricted', revision: 'r1', allowedRoots: [ROOT] });
  await assert.rejects(old, denied);
  assert.equal(state.created.length, 1);
  assert.equal(state.created[0].root, OTHER);
  assert.equal(state.created[0].closed, false);
  policy.close();
});

test('close permanently revokes, is idempotent and cannot reload again', async () => {
  const { policy, state } = fixture();
  await policy.reload();
  policy.close();policy.close();
  assert.equal(state.closed.length, 1);
  assert.equal(policy.state, 'closed');
  await assert.rejects(policy.reload(), denied);
  await assert.rejects(policy.readBytes(path.join(ROOT, 'a')), denied);
});

test('filesystem/volume root cannot masquerade as restricted policy', async () => {
  const { policy, set } = fixture();
  set({ mode: 'restricted', revision: 'r1', allowedRoots: [path.parse(ROOT).root] });
  await assert.rejects(policy.reload(), denied);
  assert.equal(policy.state, 'revoked');
});
