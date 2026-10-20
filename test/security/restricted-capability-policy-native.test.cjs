'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { RestrictedCapabilityPolicy } = require('./support/restricted-capability-policy.cjs');
const crate = path.resolve(__dirname, '../../native/capability-probe');
const binary = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
const addonFile = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
if (!fs.existsSync(addonFile)) fs.copyFileSync(binary, addonFile);
const { RootCapability } = require(addonFile);

async function withBoundary(fn) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-t011c2-'));
  const inside = path.join(base, 'allowed'), outside = path.join(base, 'outside');
  fs.mkdirSync(inside);fs.mkdirSync(outside);
  const sentinel = path.join(outside, 'sentinel.bin');
  const original = Buffer.from([0x00, 0xff, 0x80, 0x44]);
  fs.writeFileSync(sentinel, original);
  let policy;
  try {
    const context = { revision: 'r1', mode: 'restricted', allowedRoots: [inside] };
    policy = new RestrictedCapabilityPolicy({
      readVerifiedPolicy: async () => ({ ...context, allowedRoots: [...context.allowedRoots] }),
      RootCapability,
    });
    return await fn({ base, inside, outside, sentinel, original, policy, context });
  } finally {
    let cleanupError;
    try { policy?.close(); } catch (e) { cleanupError = e; }
    try { assert.deepEqual(fs.readFileSync(sentinel), original, 'Outside sentinel changed'); }
    finally { fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
    if (cleanupError) throw cleanupError;
  }
}
const denied = { code: 'E_CAPABILITY_POLICY' };

test('native capability policy permits confined binary I/O and denies external paths', async () => {
  await withBoundary(async ({ inside, sentinel, policy }) => {
    await assert.rejects(policy.readBytes(path.join(inside, 'bytes.bin')), denied);
    await policy.reload();
    const first = Buffer.from([0x00, 0xff, 0x80]);
    await policy.writeBytes(path.join(inside, 'bytes.bin'), first, 'rewrite');
    await policy.writeBytes(path.join(inside, 'bytes.bin'), Buffer.from([0x41]), 'append');
    assert.deepEqual(await policy.readBytes(path.join(inside, 'bytes.bin')),
      Buffer.from([0x00, 0xff, 0x80, 0x41]));
    await assert.rejects(policy.readBytes(sentinel), denied);
    await assert.rejects(policy.writeBytes(sentinel, Buffer.from('bad'), 'rewrite'), denied);
    await assert.rejects(policy.writeBytes(path.join(inside, '..', 'outside', 'sentinel.bin'),
      Buffer.from('bad'), 'append'), denied);
  });
});

test('native capability policy refuses external junction and never writes outside', async () => {
  await withBoundary(async ({ inside, outside, policy }) => {
    fs.symlinkSync(outside, path.join(inside, 'escape'),
      process.platform === 'win32' ? 'junction' : 'dir');
    await policy.reload();
    await assert.rejects(policy.readBytes(path.join(inside, 'escape', 'sentinel.bin')));
    await assert.rejects(policy.writeBytes(path.join(inside, 'escape', 'new.bin'),
      Buffer.from([0x11]), 'rewrite'));
    assert.equal(fs.existsSync(path.join(outside, 'new.bin')), false);
  });
});

test('verified policy revision change closes native handles and requires explicit reload', async () => {
  await withBoundary(async ({ inside, outside, policy, context }) => {
    await policy.reload();
    await policy.writeBytes(path.join(inside, 'file'), Buffer.from('before'), 'rewrite');
    context.revision = 'r2';context.allowedRoots = [outside];
    await assert.rejects(policy.writeBytes(path.join(inside, 'file'), Buffer.from('bad'), 'rewrite'), denied);
    assert.equal(policy.state, 'revoked');
    assert.equal(fs.readFileSync(path.join(inside, 'file'), 'utf8'), 'before');
    await assert.rejects(policy.readBytes(path.join(outside, 'sentinel.bin')), denied);
    await policy.reload();
    await assert.rejects(policy.readBytes(path.join(inside, 'file')), denied);
    assert.deepEqual(await policy.readBytes(path.join(outside, 'sentinel.bin')),
      Buffer.from([0x00, 0xff, 0x80, 0x44]));
  });
});

test('invalid/rejected policy cannot silently fall back to native unrestricted access', async () => {
  await withBoundary(async ({ inside, context, policy }) => {
    await policy.reload();
    context.mode = 'unrestricted';context.allowedRoots = [];
    await assert.rejects(policy.readBytes(path.join(inside, 'file')), denied);
    assert.equal(policy.state, 'revoked');
    await assert.rejects(policy.reload(), denied);
    assert.equal(policy.state, 'revoked');
  });
});

test('native policy exposes complete confined metadata, directory and deletion operations', async () => {
  await withBoundary(async ({ inside, sentinel, original, policy }) => {
    await policy.reload();
    const at = name => path.join(inside, name);
    await policy.createDirectory(at('nested'));
    const payload = Buffer.from([0x00, 0xff, 0x83, 0x21]);
    await policy.writeBytes(at('nested/original.bin'), payload, 'rewrite');
    assert.deepEqual(await policy.stat(at('nested/original.bin')),
      { kind: 'file', sizeBytes: String(payload.length) });
    assert.equal((await policy.stat(at('nested'))).kind, 'directory');
    assert.deepEqual(await policy.listDirectory(at('nested')), ['original.bin']);
    await policy.move(at('nested/original.bin'), at('nested/renamed.bin'));
    assert.deepEqual(await policy.readBytes(at('nested/renamed.bin')), payload);
    await assert.rejects(policy.removeEmptyDirectory(at('nested')));
    await policy.removeFile(at('nested/renamed.bin'));
    await policy.removeEmptyDirectory(at('nested'));
    assert.equal(fs.existsSync(at('nested')), false);
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('native policy entry operations deny junction escape and preserve external bytes', async () => {
  await withBoundary(async ({ inside, outside, sentinel, original, policy }) => {
    fs.symlinkSync(outside, path.join(inside, 'escape'),
      process.platform === 'win32' ? 'junction' : 'dir');
    await policy.reload();
    const link = path.join(inside, 'escape');
    for (const operation of [
      () => policy.stat(link),
      () => policy.stat(path.join(link, 'sentinel.bin')),
      () => policy.listDirectory(link),
      () => policy.removeFile(path.join(link, 'sentinel.bin')),
      () => policy.removeEmptyDirectory(link),
      () => policy.createDirectory(path.join(link, 'escaped')),
      () => policy.move(path.join(inside, 'safe'), path.join(link, 'escaped')),
    ]) await assert.rejects(operation());
    assert.deepEqual(fs.readFileSync(sentinel), original);
    assert.equal(fs.existsSync(path.join(outside, 'escaped')), false);
  });
});

test('native policy rechecks revision before destructive entry operations', async () => {
  await withBoundary(async ({ inside, policy, context, sentinel, original }) => {
    const target = path.join(inside, 'safe.bin');
    fs.writeFileSync(target, Buffer.from('original'));
    await policy.reload();
    context.revision = 'r2';
    await assert.rejects(policy.removeFile(target), denied);
    assert.equal(policy.state, 'revoked');
    assert.deepEqual(fs.readFileSync(target), Buffer.from('original'));
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});

test('native policy denies rename across separately allowed roots', async () => {
  await withBoundary(async ({ inside, outside, policy, context, sentinel, original }) => {
    const source = path.join(inside, 'source');
    fs.writeFileSync(source, Buffer.from('source'));
    context.allowedRoots = [inside, outside];
    await policy.reload();
    await assert.rejects(policy.move(source, path.join(outside, 'target')), denied);
    assert.equal(fs.readFileSync(source, 'utf8'), 'source');
    assert.equal(fs.existsSync(path.join(outside, 'target')), false);
    assert.deepEqual(fs.readFileSync(sentinel), original);
  });
});
