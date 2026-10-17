'use strict';
const addon = require(process.argv[2]);
const kind = process.argv[3];

const receivers = {
  object: {},
  prototype: Object.create(addon.RootCapability.prototype),
  buffer: Buffer.alloc(16),
  date: new Date(),
};
if (!Object.hasOwn(receivers, kind)) {
  process.exitCode = 3;
} else {
  try {
    addon.RootCapability.prototype.readText.call(receivers[kind], 'sentinel.txt');
    process.exitCode = 2;
  } catch (error) {
    if (!(error instanceof Error)) process.exitCode = 4;
  }
}
