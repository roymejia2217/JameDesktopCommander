'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const path = require('node:path');
const fs = require('node:fs');

test('shipping native crate contains no unsafe class implementation, even under optional features', () => {
  const sourceRoot = path.resolve(__dirname, '../../native/capability-probe');
  const manifest = fs.readFileSync(path.join(sourceRoot, 'Cargo.toml'), 'utf8');
  const nativeRoot = fs.readFileSync(path.join(sourceRoot, 'src/lib.rs'), 'utf8');
  assert.doesNotMatch(manifest, /receiver-test-fixture/,
    'a cargo feature must not reactivate unsafe receiver classes in a shipping crate');
  assert.doesNotMatch(nativeRoot, /research_impl|RootCapability/,
    'the default entry point must never depend on the unreviewed class');
  assert.equal(fs.existsSync(path.join(sourceRoot, 'src/research_impl.rs')), false,
    'unsafe class source must remain in separate non-shipping research history');
});

const releaseDir = path.resolve(__dirname, '../../native/capability-probe/target/release');
const binary = path.join(releaseDir, process.platform === 'win32'
  ? 'jdc_capability_probe.dll' : 'libjdc_capability_probe.so');
const addonFile = path.join(releaseDir, 'jdc-capability-probe.node');
test('default native artifact denies access and exports no unaudited class', () => {
  assert.ok(fs.statSync(binary).isFile(), 'native library must exist');
  fs.copyFileSync(binary, addonFile);
  const addon = require(addonFile);
  assert.deepEqual(Object.keys(addon).sort(), ['restrictedCapabilityUnavailable'],
    'default addon must have exactly one deny-only entry point');
  assert.equal(Object.hasOwn(addon, 'RootCapability'), false,
    'unproven generated receiver classes must not ship by default');
  assert.equal(typeof addon.restrictedCapabilityUnavailable, 'function');
  assert.throws(() => addon.restrictedCapabilityUnavailable(), /E_CAPABILITY_UNAVAILABLE/,
    'the default artifact must fail closed, not silently widen access');
  assert.equal(Object.hasOwn(addon, 'foreignWrappedObject'), false);
  assert.equal(Object.hasOwn(addon, 'acceptsRootArgument'), false);
  assert.equal(Object.hasOwn(addon, 'probeSharedPair'), false);
  assert.equal(Object.hasOwn(addon, 'probeSharedAndMutable'), false);
  assert.equal(Object.hasOwn(addon, 'probeMutablePair'), false);
  assert.equal(Object.hasOwn(addon, 'acceptsMutRootArgument'), false);
  assert.equal(Object.hasOwn(addon, 'probeBorrowAcrossJsCallback'), false,
    'reentrant callback fixture must not be exported without the test-only feature');
  assert.equal(Object.hasOwn(addon, 'probeNullNativeBorrow'), false,
    'null-borrow probe must not be exported without the test-only feature');
});
