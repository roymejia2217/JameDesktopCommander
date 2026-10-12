'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const crate = path.resolve(__dirname, '../../native/capability-probe');
const binary = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
const addon = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
if (!fs.existsSync(addon)) fs.copyFileSync(binary, addon);
const { RootCapability } = require(addon);

test('root acquisition rejects a redirected configured root before capability creation', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-t011-root-swap-'));
  const allowed = path.join(base, 'allowed');
  const moved = path.join(base, 'moved');
  const outside = path.join(base, 'outside');
  const sentinel = path.join(outside, 'sentinel.bin');
  const original = Buffer.from([0x00, 0xff, 0x64, 0x83]);
  let opened;
  try {
    fs.mkdirSync(allowed);
    fs.mkdirSync(outside);
    fs.writeFileSync(sentinel, original);
    opened = new RootCapability(allowed);
    opened.createDirectory('legitimate');
    assert.ok(fs.statSync(path.join(allowed, 'legitimate')).isDirectory());
    opened.close();
    opened = undefined;
    fs.renameSync(allowed, moved);
    fs.symlinkSync(outside, allowed, process.platform === 'win32' ? 'junction' : 'dir');
    assert.ok(fs.lstatSync(allowed).isSymbolicLink(), 'Attack was not installed');
    assert.equal(fs.realpathSync(allowed), fs.realpathSync(outside));
    // RED: the current ambient constructor opens the external directory.
    assert.throws(() => {
      opened = new RootCapability(allowed);
    }, /rejected|denied|symlink|reparse/i,
    'A redirected configured root must never become the native authorization root');
  } finally {
    opened?.close();
    try {
      if (fs.existsSync(sentinel)) {
        assert.deepEqual(fs.readFileSync(sentinel), original,
          'The outside sentinel changed during the root-acquisition test');
      }
    } finally {
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
});

test('root acquisition rejects an intermediate junction or symlink', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-t011-root-mid-'));
  const allowed = path.join(base, 'allowed');
  const segment = path.join(allowed, 'segment');
  const displaced = path.join(allowed, 'displaced');
  const outside = path.join(base, 'outside');
  const safeRoot = path.join(segment, 'nested');
  const outsideRoot = path.join(outside, 'nested');
  const sentinel = path.join(outsideRoot, 'sentinel.bin');
  const original = Buffer.from([0x27, 0x00, 0xfd]);
  let opened;
  try {
    fs.mkdirSync(safeRoot, { recursive: true });
    fs.mkdirSync(outsideRoot, { recursive: true });
    fs.writeFileSync(sentinel, original);
    opened = new RootCapability(safeRoot);
    opened.close();
    opened = undefined;
    fs.renameSync(segment, displaced);
    fs.symlinkSync(outside, segment, process.platform === 'win32' ? 'junction' : 'dir');
    assert.ok(fs.lstatSync(segment).isSymbolicLink(), 'Intermediate attack not installed');
    assert.equal(fs.realpathSync(safeRoot), fs.realpathSync(outsideRoot));
    assert.throws(() => { opened = new RootCapability(safeRoot); },
      /rejected|denied|symlink|reparse/i,
      'No intermediate namespace alias may become an authorized root');
  } finally {
    opened?.close();
    try {
      if (fs.existsSync(sentinel)) {
        assert.deepEqual(fs.readFileSync(sentinel), original,
          'Outside sentinel changed during intermediate swap');
      }
    } finally {
      fs.rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
});
