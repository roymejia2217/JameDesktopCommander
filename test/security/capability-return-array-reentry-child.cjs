'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Research-only, bounded child-process probe. No privileged service or MCP calls.
assert.equal(typeof global.gc, 'function', 'child requires --expose-gc');
const addon = require(process.argv[2]);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-return-reentry-'));
let capability;
let insideCall = false;
let nestedCalls = 0;
let setterCalls = 0;
let injectFailure = false;
let sawFailureSetter = false;
const previous = Object.getOwnPropertyDescriptor(Array.prototype, '1');
assert.equal(previous, undefined, 'test requires an unmodified Array.prototype[1]');
try {
  fs.writeFileSync(path.join(root, 'readback.txt'), 'KNOWN-CONTENT');
  for (let i = 0; i < 5; i++) {
    fs.writeFileSync(path.join(root, 'entry-' + i + '.txt'), 'entry');
  }
  capability = new addon.RootCapability(root);
  Object.defineProperty(Array.prototype, '1', {
    configurable: true,
    set(value) {
      setterCalls++;
      if (insideCall && injectFailure) {
        sawFailureSetter = true;
        throw new Error('JDC_TEST_RETURN_CONVERSION_EXCEPTION');
      }
      if (insideCall && nestedCalls === 0) {
        nestedCalls++;
        assert.equal(capability.readText('readback.txt'), 'KNOWN-CONTENT',
          'reentrant shared native receiver must complete while array is created');
        assert.throws(() => addon.acceptsMutRootArgument(capability),
          /borrow|mutabl|exclusive|active/i,
          'outer return conversion must retain its native shared borrow guard');
        global.gc();
      }
      Object.defineProperty(this, '1', {
        configurable: true, enumerable: true, writable: true, value,
      });
    },
  });
  let names;
  try {
    insideCall = true;
    names = capability.listDirectory('.');
  } finally {
    insideCall = false;
  }
  assert.equal(nestedCalls, 1,
    'native Vec<String> conversion must invoke the inherited index setter');
  assert.ok(names.includes('readback.txt'), 'directory conversion must return valid results');
  assert.ok(setterCalls >= 1);
  assert.equal(addon.acceptsMutRootArgument(capability), true,
    'exclusive borrow must recover after array conversion completes');
  injectFailure = true;
  try {
    insideCall = true;
    assert.throws(() => capability.listDirectory('.'), Error,
      'an inherited setter error during native return conversion must propagate');
  } finally {
    insideCall = false;
    injectFailure = false;
  }
  assert.equal(sawFailureSetter, true, 'exception must originate in the inherited setter');
  assert.equal(addon.acceptsMutRootArgument(capability), true,
    'the generated native borrow guard must release on return-conversion error');
  assert.equal(capability.readText('readback.txt'), 'KNOWN-CONTENT',
    'native capability remains usable after an exceptional return conversion');
  console.log('PRODUCTION_RECEIVER_REENTRY_OBSERVED=' + nestedCalls);
  console.log('RETURN_CONVERSION_EXCEPTION_GUARD_RELEASED=1');
} finally {
  insideCall = false;
  if (previous) Object.defineProperty(Array.prototype, '1', previous);
  else delete Array.prototype[1];
  capability?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
