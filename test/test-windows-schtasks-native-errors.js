import assert from 'node:assert/strict';
import { test } from 'node:test';
import koffi from 'koffi';

test('Win32 API failure and invalid directory fail closed without environment fallback', {
  skip: process.platform !== 'win32',
}, async () => {
  const original = koffi.load;
  let next = null;
  koffi.load = () => ({ func: () => (buffer) => {
    if (next === null) return 0;
    buffer.write(next, 0, 'utf16le');
    return next.length;
  } });
  try {
    const { resolveSchtasksExecutable } = await import(
      '../dist/platform/windows/scheduled-task.js?native-error-fixture'
    );
    const environment = { SystemRoot: 'C:\\JDC-ATTACKER-CONTROLLED' };
    assert.throws(() => resolveSchtasksExecutable(environment), /could not be determined/);
    next = '\\\\remote\\share\\system32';
    assert.throws(() => resolveSchtasksExecutable(environment), /invalid system directory/);
    next = 'C:\\outside\\..\\system32';
    assert.throws(() => resolveSchtasksExecutable(environment), /invalid system directory/);
  } finally {
    koffi.load = original;
  }
});
