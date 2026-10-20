'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Research-only, bounded child-process probe. No privileged service or MCP calls.
const addon = require(process.argv[2]);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-return-reentry-'));
let capability;
let insideCall = false;
let nestedCalls = 0;
let setterCalls = 0;
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
      if (insideCall && nestedCalls === 0) {
        nestedCalls++;
        assert.equal(capability.readText('readback.txt'), 'KNOWN-CONTENT',
          'reentrant shared native receiver must complete while array is created');
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
  console.log('PRODUCTION_RECEIVER_REENTRY_OBSERVED=' + nestedCalls);
} finally {
  insideCall = false;
  if (previous) Object.defineProperty(Array.prototype, '1', previous);
  else delete Array.prototype[1];
  capability?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
