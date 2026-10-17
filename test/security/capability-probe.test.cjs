'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crate = path.resolve(__dirname, '../../native/capability-probe');
const binary = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
assert.ok(fs.statSync(binary).isFile(), 'CI must build the native probe');
const addon = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
fs.copyFileSync(binary, addon);
const { RootCapability } = require(addon);
assert.equal(typeof RootCapability, 'function');

function withFixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-cap-poc-'));
  const allowed = path.join(root, 'allowed'), outside = path.join(root, 'outside');
  fs.mkdirSync(allowed); fs.mkdirSync(outside);
  const outsideFile = path.join(outside, 'sentinel.txt');
  fs.writeFileSync(outsideFile, 'untouched\n');
  let cap;
  try {
    cap = new RootCapability(allowed);
    return fn({ root, allowed, outside, outsideFile, cap });
  } finally {
    cap?.close();
    try {
      assert.equal(fs.readFileSync(outsideFile, 'utf8'), 'untouched\n',
        'Outside sentinel was modified');
    } finally {
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
}
test('native read, rewrite, append, close', () => {
  withFixture(({ cap, allowed }) => {
    cap.writeText('inside.txt', 'one\n'); cap.appendText('inside.txt', 'two\n');
    assert.equal(cap.readText('inside.txt'), 'one\ntwo\n');
    assert.equal(fs.readFileSync(path.join(allowed, 'inside.txt'), 'utf8'), 'one\ntwo\n');
    cap.close();
    assert.throws(() => cap.readText('inside.txt'), /closed/i);
    assert.throws(() => cap.writeText('inside.txt', 'forbidden'), /closed/i);
  });
});
test('parent traversal and absolute paths cannot escape', () => {
  withFixture(({ cap, outsideFile }) => {
    assert.throws(() => cap.readText(path.join('..', 'outside', 'sentinel.txt')));
    assert.throws(() => cap.writeText(path.join('..', 'outside', 'sentinel.txt'), 'bad'));
    assert.throws(() => cap.writeText(outsideFile, 'bad'));
  });
});
test('directory symlink or junction cannot escape', () => {
  withFixture(({ cap, allowed, outside }) => {
    fs.symlinkSync(outside, path.join(allowed, 'escape'),
      process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => cap.readText(path.join('escape', 'sentinel.txt')));
    assert.throws(() => cap.writeText(path.join('escape', 'sentinel.txt'), 'bad'));
    assert.throws(() => cap.writeText(path.join('escape', 'created.txt'), 'bad'));
    assert.equal(fs.existsSync(path.join(outside, 'created.txt')), false);
  });
});
test('open root capability resists replacement of original pathname', () => {
  withFixture(({ cap, root, allowed, outside }) => {
    const moved = path.join(root, 'moved');
    try {
      fs.renameSync(allowed, moved);
    } catch (error) {
      assert.equal(process.platform, 'win32');
      assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code));
      cap.writeText('anchored.txt', 'safe\n');
      assert.equal(fs.readFileSync(path.join(allowed, 'anchored.txt'), 'utf8'), 'safe\n');
      return;
    }
    fs.symlinkSync(outside, allowed, process.platform === 'win32' ? 'junction' : 'dir');
    try {
      cap.writeText('anchored.txt', 'safe\n');
      assert.equal(fs.readFileSync(path.join(moved, 'anchored.txt'), 'utf8'), 'safe\n');
      assert.equal(fs.existsSync(path.join(outside, 'anchored.txt')), false);
    } finally {
      fs.unlinkSync(allowed);
    }
  });
});
test('patched Windows special device-name variants are denied',
  { skip: process.platform !== 'win32' }, () => {
    withFixture(({ cap }) => {
      assert.throws(() => cap.writeText('COM¹', 'bad'));
      assert.throws(() => cap.readText('LPT¹'));
    });
  });

const MAX_CAPABILITY_BYTES = 32 * 1024 * 1024;

test('binary capability preserves non-UTF8 bytes, NUL, rewrite and append', () => {
  withFixture(({ cap, allowed }) => {
    const first = Buffer.from([0x00, 0xff, 0x80, 0x41, 0x0a]);
    const second = Buffer.from([0xc0, 0x00, 0x7f]);
    cap.writeBytes('payload.bin', first, 'rewrite');
    assert.deepEqual(cap.readBytes('payload.bin'), first);
    cap.writeBytes('payload.bin', second, 'append');
    assert.deepEqual(cap.readBytes('payload.bin'), Buffer.concat([first, second]));
    assert.deepEqual(fs.readFileSync(path.join(allowed, 'payload.bin')),
      Buffer.concat([first, second]));
    cap.close();
    assert.throws(() => cap.readBytes('payload.bin'), /closed/i);
    assert.throws(() => cap.writeBytes('payload.bin', first, 'rewrite'), /closed/i);
  });
});

test('binary operations reject traversal, absolute paths and escaping junctions', () => {
  withFixture(({ cap, allowed, outside, outsideFile }) => {
    const payload = Buffer.from('forbidden');
    const escape = path.join(allowed, 'escape');
    fs.symlinkSync(outside, escape, process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => cap.readBytes(path.join('..', 'outside', 'sentinel.txt')));
    assert.throws(() => cap.writeBytes(path.join('..', 'outside', 'sentinel.txt'),
      payload, 'rewrite'));
    assert.throws(() => cap.writeBytes(outsideFile, payload, 'append'));
    assert.throws(() => cap.readBytes(path.join('escape', 'sentinel.txt')));
    assert.throws(() => cap.writeBytes(path.join('escape', 'sentinel.txt'),
      payload, 'rewrite'));
    assert.throws(() => cap.writeBytes(path.join('escape', 'new.bin'),
      payload, 'rewrite'));
    assert.equal(fs.existsSync(path.join(outside, 'new.bin')), false);
  });
});

test('invalid binary mode and oversized write leave existing content unchanged', () => {
  withFixture(({ cap, allowed }) => {
    const original = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    cap.writeBytes('existing.bin', original, 'rewrite');
    assert.throws(() => cap.writeBytes('existing.bin', Buffer.from('evil'), 'invalid'),
      /Invalid capability write mode/);
    const oversized = Buffer.alloc(MAX_CAPABILITY_BYTES + 1);
    assert.throws(() => cap.writeBytes('existing.bin', oversized, 'rewrite'),
      /Capability byte limit exceeded/);
    assert.throws(() => cap.writeBytes('missing.bin', oversized, 'append'),
      /Capability byte limit exceeded/);
    assert.deepEqual(fs.readFileSync(path.join(allowed, 'existing.bin')), original);
    assert.equal(fs.existsSync(path.join(allowed, 'missing.bin')), false);
  });
});

test('oversized binary reads are explicitly denied instead of truncated', () => {
  withFixture(({ cap, allowed }) => {
    const large = path.join(allowed, 'large.bin');
    fs.writeFileSync(large, Buffer.from([0x23]));
    fs.truncateSync(large, MAX_CAPABILITY_BYTES + 1);
    assert.throws(() => cap.readBytes('large.bin'), /Capability byte limit exceeded/);
    assert.equal(fs.statSync(large).size, MAX_CAPABILITY_BYTES + 1);
  });
});

test('N-API rejects invalid JavaScript receivers without crashing', () => {
  const { spawnSync } = require('node:child_process');
  const child = path.join(__dirname, 'capability-receiver-child.cjs');
  const receivers = ['object', 'prototype', 'buffer', 'date'];
  for (const receiver of receivers) {








    const result = spawnSync(process.execPath, [child, addon, receiver], {
      timeout: 10_000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 128 * 1024,
    });
    assert.equal(result.error, undefined, receiver + ': child process error');
    assert.equal(result.signal, null, receiver + ': native process terminated by signal');
    assert.equal(result.status, 0, receiver + ': unexpected native termination or acceptance: ' + result.stderr);
  }
});
