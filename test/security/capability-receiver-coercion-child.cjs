'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const addon = require(process.argv[2]);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-receiver-coercion-'));
const sample = path.join(root, 'sample.txt');
fs.writeFileSync(sample, 'RECEIVER-GUARD-CONTROL');
let capability;
try {
  capability = new addon.RootCapability(root);
  const accesses = [];
  const suspicious = {
    get [Symbol.toPrimitive]() {
      accesses.push('symbol-primitive');
      assert.equal(capability.readText('sample.txt'), 'RECEIVER-GUARD-CONTROL');
      return () => 'sample.txt';
    },
    toString() {
      accesses.push('toString');
      assert.equal(capability.readText('sample.txt'), 'RECEIVER-GUARD-CONTROL');
      return 'sample.txt';
    },
    valueOf() {
      accesses.push('valueOf');
      assert.equal(capability.readText('sample.txt'), 'RECEIVER-GUARD-CONTROL');
      return 'sample.txt';
    },
  };
  const cases = [
    ['readText', () => capability.readText(suspicious)],
    ['readBytes', () => capability.readBytes(suspicious)],
    ['writeText', () => capability.writeText(suspicious, 'DENIED')],
    ['writeBytes', () => capability.writeBytes(suspicious, Buffer.from('DENIED'), 'rewrite')],
    ['appendText', () => capability.appendText(suspicious, 'DENIED')],
    ['listDirectory', () => capability.listDirectory(suspicious)],
    ['createDirectory', () => capability.createDirectory(suspicious)],
    ['moveRelative', () => capability.moveRelative(suspicious, 'other.txt')],
  ];
  for (const [name, operation] of cases) {
    assert.throws(operation, Error, name + ': object path must be denied');
    assert.deepEqual(accesses, [], name + ': path conversion must not run user JavaScript');
    assert.equal(fs.readFileSync(sample, 'utf8'), 'RECEIVER-GUARD-CONTROL',
      name + ': rejected path must not modify the file');
  }
} finally {
  capability?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
