'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const path = require('node:path');
const fs = require('node:fs');

const addonFile = path.resolve(__dirname,
  '../../native/capability-probe/target/release/jdc-capability-probe.node');
test('default native artifact does not export CI-only receiver fixtures', () => {
  assert.ok(fs.statSync(addonFile).isFile(), 'native artifact must exist');
  const addon = require(addonFile);
  assert.equal(typeof addon.RootCapability, 'function');
  assert.equal(Object.hasOwn(addon, 'ForeignCapabilityReceiver'), false);
  assert.equal(Object.hasOwn(addon, 'acceptsRootArgument'), false);
});
