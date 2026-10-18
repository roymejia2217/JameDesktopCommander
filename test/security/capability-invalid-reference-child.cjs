'use strict';
const assert = require('node:assert/strict');
const addon = require(process.argv[2]);
const kind = process.argv[3];

const candidates = {
  null: null,
  undefined: undefined,
  number: 0,
  string: 'untrusted',
  boolean: false,
  'plain-object': {},
  'null-prototype': Object.create(null),
  'spoofed-prototype': Object.create(addon.RootCapability.prototype),
  'proxy-object': new Proxy({}, {}),
  buffer: Buffer.alloc(8),
};
assert.ok(Object.hasOwn(candidates, kind), 'unknown invalid reference fixture');
for (const [name, convert] of [
  ['FromNapiRef', addon.acceptsRootArgument],
  ['FromNapiMutRef', addon.acceptsMutRootArgument],
]) {
  assert.throws(
    () => convert(candidates[kind]),
    Error,
    kind + ': ' + name + ' must reject an unwrapped JavaScript value',
  );
}
