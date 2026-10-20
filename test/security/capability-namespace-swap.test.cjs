'use strict';

// T011 direct security work: exercised post-authorization swaps against the
// native capability handle, not an isolated/mock policy-state simulation.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const crate = path.resolve(__dirname, '../../native/capability-probe');
const dll = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
assert.ok(fs.statSync(dll).isFile(), 'Native proof MUST compile on this OS');
const addon = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
fs.copyFileSync(dll, addon);
const { RootCapability } = require(addon);
assert.equal(typeof RootCapability, 'function');

function withIsolatedRoot(callback) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-t011-real-swap-'));
  const allowed = path.join(base, 'allowed');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(allowed);
  fs.mkdirSync(outside);
  const sentinel = path.join(outside, 'sentinel.bin');
  const original = Buffer.from([0x00, 0xff, 0x81, 0x77, 0x10]);
  fs.writeFileSync(sentinel, original);
  const cap = new RootCapability(allowed);
  let error;
  try {
    callback({ base, allowed, outside, sentinel, original, cap });
  } catch (cause) {
    error = cause;
  } finally {
    try {
      cap.close();
      assert.deepEqual(fs.readFileSync(sentinel), original,
        'Outside sentinel bytes changed during a native capability test');
    } catch (verificationError) {
      error = error
        ? new AggregateError([error, verificationError], 'Operation and outside integrity failed')
        : verificationError;
    } finally {
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
  if (error) throw error;
}

test('handle-relative mkdir, rename and list permit valid in-root work and deny traversal', () => {
  withIsolatedRoot(({ cap, allowed }) => {
    cap.createDirectory('a/b');
    cap.writeBytes(path.join('a', 'b', 'from.bin'), Buffer.from([0xff, 0x00]), 'rewrite');
    cap.moveRelative(path.join('a', 'b', 'from.bin'), path.join('a', 'b', 'to.bin'));
    assert.deepEqual(cap.listDirectory('a/b'), ['to.bin']);
    assert.deepEqual(cap.readBytes('a/b/to.bin'), Buffer.from([0xff, 0x00]));
    assert.deepEqual(fs.readFileSync(path.join(allowed, 'a', 'b', 'to.bin')),
      Buffer.from([0xff, 0x00]));

    assert.throws(() => cap.createDirectory('../outside/escaped'));
    assert.throws(() => cap.moveRelative('a/b/to.bin', '../outside/escaped'));
    assert.throws(() => cap.moveRelative('../outside/sentinel.bin', 'a/b/escaped'));
    assert.throws(() => cap.listDirectory('../outside'));
    assert.equal(fs.existsSync(path.join(allowed, 'a', 'b', 'to.bin')), true);
  });
});

test('real intermediate directory swap after pathname checkpoint cannot escape capability', () => {
  withIsolatedRoot(({ cap, allowed, outside, sentinel, original }) => {
    const gate = path.join(allowed, 'gate');
    const displaced = path.join(allowed, 'displaced-gate');
    const child = path.join(gate, 'inside.bin');
    const nativeFrom = path.join(allowed, 'safe-source.bin');
    fs.mkdirSync(gate);
    fs.writeFileSync(child, Buffer.from('internal'));
    fs.writeFileSync(nativeFrom, Buffer.from('source'));

    // Demonstrate that a pathname authorization checkpoint succeeded BEFORE
    // the namespace change. There is deliberately no vulnerable production
    // handler call in this fixture; only the native cap-std operations execute.
    assert.equal(fs.realpathSync(gate), path.join(fs.realpathSync(allowed), 'gate'));
    assert.equal(fs.readFileSync(child, 'utf8'), 'internal');

    fs.renameSync(gate, displaced);
    let swapInstalled = false;
    try {
      fs.symlinkSync(outside, gate, process.platform === 'win32' ? 'junction' : 'dir');
      swapInstalled = true;
      // A test in which the swap was blocked must FAIL, not count as proof.
      assert.ok(fs.lstatSync(gate).isSymbolicLink(), 'Namespace swap was not installed');
      assert.equal(fs.realpathSync(gate), fs.realpathSync(outside), 'Attacker-controlled path not reached');
      assert.deepEqual(fs.readFileSync(path.join(gate, 'sentinel.bin')), original);

      assert.throws(() => cap.writeBytes('gate/sentinel.bin',
        Buffer.from('outside write'), 'rewrite'));
      assert.throws(() => cap.readBytes('gate/sentinel.bin'));
      assert.throws(() => cap.statRelative('gate/sentinel.bin'));
      assert.throws(() => cap.removeFileRelative('gate/sentinel.bin'));
      assert.throws(() => cap.removeEmptyDirectoryRelative('gate'));
      assert.throws(() => cap.createDirectory('gate/created-outside'));
      assert.throws(() => cap.listDirectory('gate'));
      assert.throws(() => cap.moveRelative('safe-source.bin', 'gate/moved-outside.bin'));
      assert.throws(() => cap.moveRelative('gate/sentinel.bin', 'stolen.bin'));

      assert.deepEqual(fs.readFileSync(sentinel), original);
      assert.equal(fs.existsSync(path.join(outside, 'created-outside')), false);
      assert.equal(fs.existsSync(path.join(outside, 'moved-outside.bin')), false);
      assert.deepEqual(fs.readFileSync(nativeFrom), Buffer.from('source'));
      assert.equal(fs.existsSync(path.join(allowed, 'stolen.bin')), false);
    } finally {
      if (swapInstalled) fs.unlinkSync(gate);
      fs.renameSync(displaced, gate);
    }

    // In-root operations still work immediately after the namespace recovers.
    cap.createDirectory('gate/recovered');
    cap.writeBytes('gate/recovered/inside.bin', Buffer.from([0x11, 0x22]), 'rewrite');
    assert.deepEqual(cap.readBytes('gate/recovered/inside.bin'), Buffer.from([0x11, 0x22]));
  });
});

test('closed handle fails for all added directory operations', () => {
  withIsolatedRoot(({ cap }) => {
    cap.close();
    assert.throws(() => cap.createDirectory('nope'), /closed/i);
    assert.throws(() => cap.moveRelative('from', 'to'), /closed/i);
    assert.throws(() => cap.listDirectory('.'), /closed/i);
    assert.throws(() => cap.statRelative('.'), /closed/i);
    assert.throws(() => cap.removeFileRelative('nope'), /closed/i);
    assert.throws(() => cap.removeEmptyDirectoryRelative('nope'), /closed/i);
  });
});
