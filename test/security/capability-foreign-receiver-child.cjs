'use strict';
const assert = require('node:assert/strict');
const addon = require(process.argv[2]);
const method = process.argv[3];
const receiver = addon.foreignWrappedObject();
receiver.marker = 'unchanged';

if (method === 'argument') {
  assert.throws(
    () => addon.acceptsRootArgument(receiver),
    /not an instance of class.*RootCapability/i,
    'FromNapiRef must validate native identity before constructing &RootCapability',
  );
} else {
  const args = {
    readText: ['sentinel.txt'],
    readBytes: ['sentinel.bin'],
    writeText: ['sentinel.txt', 'forbidden'],
    close: [],
  };
  assert.ok(Object.hasOwn(args, method), 'unknown N-API method');
  assert.throws(
    () => addon.RootCapability.prototype[method].apply(receiver, args[method]),
    Error,
    'method must reject foreign N-API receiver',
  );
}
assert.equal(receiver.marker, 'unchanged', 'foreign wrapped object must remain intact');
