'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const path = require('node:path');
const fs = require('node:fs');

const releaseDir = path.resolve(__dirname, '../../native/capability-probe/target/release');
const binary = path.join(releaseDir, process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
const addonFile = path.join(releaseDir, 'jdc-capability-probe.node');
test('default native artifact does not export CI-only receiver fixtures', () => {
  assert.ok(fs.statSync(binary).isFile(), 'native library must exist');
  fs.copyFileSync(binary, addonFile);
  const addon = require(addonFile);
  assert.equal(typeof addon.RootCapability, 'function');
  assert.equal(Object.hasOwn(addon, 'foreignWrappedObject'), false);
  assert.equal(Object.hasOwn(addon, 'acceptsRootArgument'), false);
  assert.equal(Object.hasOwn(addon, 'probeSharedPair'), false);
  assert.equal(Object.hasOwn(addon, 'probeSharedAndMutable'), false);
  assert.equal(Object.hasOwn(addon, 'probeMutablePair'), false);
  assert.equal(Object.hasOwn(addon, 'acceptsMutRootArgument'), false);
});
