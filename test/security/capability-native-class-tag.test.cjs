'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const crate = path.resolve(__dirname, '../../native/capability-probe');
const dylib = path.join(crate, 'target', 'release', process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
const addonFile = path.join(crate, 'target', 'release', 'jdc-capability-probe.node');
const child = path.join(__dirname, 'capability-foreign-receiver-child.cjs');
assert.ok(fs.statSync(dylib).isFile(), 'build non-release receiver fixture before testing');
fs.copyFileSync(dylib, addonFile);
const addon = require(addonFile);
assert.equal(typeof addon.ForeignCapabilityReceiver, 'function',
  'receiver-test-fixture feature must be enabled in the non-release build');

for (const method of ['readText', 'readBytes', 'writeText', 'close', 'argument']) {
  test('native type tag rejects foreign receiver for ' + method, () => {
    const result = spawnSync(process.execPath, [child, addonFile, method], {
      timeout: 10_000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 128 * 1024,
    });
    assert.equal(result.error, undefined, 'bounded native child must finish');
    assert.equal(result.signal, null, 'native process must not crash');
    assert.equal(result.status, 0, method + ': ' + result.stderr);
  });
}

test('native type tag accepts a legitimate RootCapability argument', () => {
  const os = require('node:os');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-napi-tag-'));
  let cap;
  try {
    cap = new addon.RootCapability(root);
    assert.equal(addon.acceptsRootArgument(cap), true);
  } finally {
    cap?.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
