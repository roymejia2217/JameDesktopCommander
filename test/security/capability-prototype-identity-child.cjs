'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const addon = require(process.argv[2]);
const kind = process.argv[3];

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jdc-napi-proto-'));
let capability;
try {
  capability = new addon.RootCapability(root);
  const convert = [addon.acceptsRootArgument, addon.acceptsMutRootArgument];
  if (kind === 'authentic-prototype-replaced') {
    const original = Object.getPrototypeOf(capability);
    try {
      Object.setPrototypeOf(capability, null);
      for (const fn of convert) {
        assert.equal(fn(capability), true,
          'native identity must survive a JavaScript prototype replacement');
      }
    } finally {
      Object.setPrototypeOf(capability, original);
    }
  } else {
    const candidates = {
      'inherited-wrapper': () => Object.create(capability),
      'proxied-wrapper': () => new Proxy(capability, {}),
      'foreign-realm': () => vm.runInNewContext('({})'),
    };
    assert.ok(Object.hasOwn(candidates, kind), 'unknown prototype identity case');
    const receiver = candidates[kind]();
    for (const fn of convert) {
      assert.throws(() => fn(receiver), Error,
        kind + ': unwrapped or proxied value must not gain native identity');
    }
  }
} finally {
  capability?.close();
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
