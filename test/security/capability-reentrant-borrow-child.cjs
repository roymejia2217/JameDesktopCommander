'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

assert.equal(typeof global.gc, 'function', 'child must run with --expose-gc');
const addon = require(process.argv[2]);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-napi-reentrant-'));
let capability;
try {
  capability = new addon.RootCapability(root);
  let callbacks = 0;
  for (let i = 0; i < 6; i++) {
    assert.equal(addon.probeBorrowAcrossJsCallback(capability, () => {
      callbacks += 1;
      global.gc();
      global.gc();
      assert.equal(addon.acceptsRootArgument(capability), true,
        'shared reentrant conversion must remain legal');
      assert.throws(() => addon.acceptsMutRootArgument(capability),
        /borrow|mutabl|exclusive|active/i,
        'reentrant mutable alias must be denied while shared borrow is live');
    }), true);
    assert.equal(addon.acceptsMutRootArgument(capability), true,
      'exclusive borrow must be available after outer callback returns');
  }
  assert.equal(callbacks, 6);
  // Unlike the exported free function above, this path exercises the
  // napi-derive-generated &self method receiver conversion directly.
  let nestedReceiverCalls = 0;
  for (let i = 0; i < 4; i++) {
    assert.equal(capability.probeReceiverAcrossJsCallback(() => {
      global.gc();
      assert.equal(capability.probeReceiverAcrossJsCallback(() => {
        nestedReceiverCalls += 1;
        assert.equal(addon.acceptsRootArgument(capability), true);
      }), true);
      assert.throws(() => addon.acceptsMutRootArgument(capability),
        /borrow|mutabl|exclusive|active/i,
        'nested receiver must retain the shared borrow');
    }), true);
    assert.equal(addon.acceptsMutRootArgument(capability), true,
      'native method receiver guards must release after return');
  }
  assert.equal(nestedReceiverCalls, 4);
  assert.throws(() => capability.probeReceiverAcrossJsCallback(() => {
    global.gc();
    throw new Error('deliberate native receiver callback failure');
  }), /deliberate native receiver callback failure|Call Function failed|pending exception/i,
  'generated receiver callback exception must be propagated');
  assert.equal(addon.acceptsMutRootArgument(capability), true,
    'generated receiver borrow must release after callback failure');
  assert.throws(() => addon.probeBorrowAcrossJsCallback(capability, () => {
    global.gc();
    throw new Error('deliberate reentrant callback failure');
  }), Error, 'exceptional callback must propagate an error');
  assert.equal(addon.acceptsMutRootArgument(capability), true,
    'callback failure must release the shared borrow guard');
} finally {
  capability?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
