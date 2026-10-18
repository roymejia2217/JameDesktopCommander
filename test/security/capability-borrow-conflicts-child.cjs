'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const addon = require(process.argv[2]);
const kind = process.argv[3];
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-napi-borrow-'));
let first, second;
try {
  const a = path.join(root, 'a');
  const b = path.join(root, 'b');
  fs.mkdirSync(a);
  fs.mkdirSync(b);
  first = new addon.RootCapability(a);
  second = new addon.RootCapability(b);
  const scenarios = {
    'shared-same': () => assert.equal(addon.probeSharedPair(first, first), true),
    'shared-distinct': () => assert.equal(addon.probeSharedPair(first, second), true),
    'shared-mutable-same': () => assert.throws(
      () => addon.probeSharedAndMutable(first, first), /borrow|mutabl|exclusive|active/i),
    'mutable-pair-same': () => assert.throws(
      () => addon.probeMutablePair(first, first), /borrow|mutabl|exclusive|active/i),
    'mixed-distinct': () => {
      assert.equal(addon.probeSharedAndMutable(first, second), true);
      assert.equal(addon.probeMutablePair(first, second), true);
    },
  };
  assert.ok(Object.hasOwn(scenarios, kind), 'unknown native borrow scenario');
  scenarios[kind]();
  // A rejected argument conversion must release all guards from its attempt.
  assert.equal(addon.acceptsRootArgument(first), true);
  assert.equal(addon.acceptsMutRootArgument(first), true);
  assert.equal(addon.probeMutablePair(first, second), true);
} finally {
  first?.close();
  second?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
