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
assert.equal(typeof addon.foreignWrappedObject, 'function',
  'receiver-test-fixture feature must be enabled in the non-release build');

for (const method of ['readText', 'readBytes', 'writeText', 'close', 'argument', 'mutArgument']) {
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

test('native borrow guard rejects null before shared or exclusive Rust references exist', () => {
  assert.equal(typeof addon.probeNullNativeBorrow, 'function',
    'test-only native borrow rejection fixture must be present');
  for (const mutable of [false, true]) {
    assert.throws(
      () => addon.probeNullNativeBorrow(mutable),
      /Cannot borrow a null native value/,
      (mutable ? 'exclusive' : 'shared') + ' null pointer must be denied',
    );
  }
});

test('reentrant JS and GC cannot violate an active shared native borrow', () => {
  const reentry = path.join(__dirname, 'capability-reentrant-borrow-child.cjs');
  const result = spawnSync(process.execPath, ['--expose-gc', reentry, addonFile], {
    timeout: 15_000,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 128 * 1024,
  });
  assert.equal(result.error, undefined, 'bounded reentry child must finish');
  assert.equal(result.signal, null, 'reentrant GC must not crash the native runtime');
  assert.equal(result.status, 0, result.stderr);
});

test('production native methods reject object paths without invoking user coercion', () => {
  const probe = path.join(__dirname, 'capability-receiver-coercion-child.cjs');
  const result = spawnSync(process.execPath, [probe, addonFile], {
    timeout: 15_000,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 128 * 1024,
  });
  assert.equal(result.error, undefined, 'bounded coercion child must finish');
  assert.equal(result.signal, null, 'coercion must not crash the native runtime');
  assert.equal(result.status, 0, result.stderr);
});

test('listDirectory return conversion can reenter a production shared receiver', () => {
  const child = path.join(__dirname, 'capability-return-array-reentry-child.cjs');
  const result = spawnSync(process.execPath, ['--expose-gc', child, addonFile], {
    timeout: 15_000,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 128 * 1024,
  });
  assert.equal(result.error, undefined, 'bounded return-conversion child must finish');
  assert.equal(result.signal, null, 'native runtime must not crash');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PRODUCTION_RECEIVER_REENTRY_OBSERVED=1/,
    'the test must actually trigger nested JS during native return conversion');
  assert.match(result.stdout, /RETURN_CONVERSION_EXCEPTION_GUARD_RELEASED=1/,
    'the exceptional return-conversion path must release native borrow guards');
});

test('native type tag accepts a legitimate RootCapability argument', () => {
  const os = require('node:os');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-napi-tag-'));
  let cap;
  try {
    cap = new addon.RootCapability(root);
    assert.equal(addon.acceptsRootArgument(cap), true);
    assert.equal(addon.acceptsMutRootArgument(cap), true);
  } finally {
    cap?.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('native shared and mutable references reject invalid JavaScript inputs', () => {
  const inputChild = path.join(__dirname, 'capability-invalid-reference-child.cjs');
  const kinds = [
    'null', 'undefined', 'number', 'string', 'boolean',
    'plain-object', 'null-prototype', 'spoofed-prototype', 'proxy-object', 'buffer',
  ];
  for (const kind of kinds) {
    const result = spawnSync(process.execPath, [inputChild, addonFile, kind], {
      timeout: 10_000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 128 * 1024,
    });
    assert.equal(result.error, undefined, kind + ': child process must complete');
    assert.equal(result.signal, null, kind + ': must not crash native runtime');
    assert.equal(result.status, 0, kind + ': ' + result.stderr);
  }
});

for (const kind of [
  'authentic-prototype-replaced', 'inherited-wrapper',
  'proxied-wrapper', 'foreign-realm',
]) {
  test('native class identity is independent of JavaScript prototype: ' + kind, () => {
    const childProcess = path.join(__dirname, 'capability-prototype-identity-child.cjs');
    const result = spawnSync(process.execPath, [childProcess, addonFile, kind], {
      timeout: 10_000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 128 * 1024,
    });
    assert.equal(result.error, undefined, kind + ': bounded child must finish');
    assert.equal(result.signal, null, kind + ': native runtime must not crash');
    assert.equal(result.status, 0, kind + ': ' + result.stderr);
  });
}

for (const kind of [
  'shared-same', 'shared-distinct', 'shared-mutable-same',
  'mutable-pair-same', 'mixed-distinct',
]) {
  test('native borrow guard preserves aliasing invariant: ' + kind, () => {
    const childProcess = path.join(__dirname, 'capability-borrow-conflicts-child.cjs');
    const result = spawnSync(process.execPath, [childProcess, addonFile, kind], {
      timeout: 10_000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 128 * 1024,
    });
    assert.equal(result.error, undefined, kind + ': bounded child must finish');
    assert.equal(result.signal, null, kind + ': native runtime must not crash');
    assert.equal(result.status, 0, kind + ': ' + result.stderr);
  });
}
