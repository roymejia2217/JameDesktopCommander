import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  resolveSchtasksExecutable,
  runWindowsScheduledTaskAction,
} from '../dist/platform/windows/scheduled-task.js';

test('Win32 schtasks resolution ignores a forged SystemRoot in process and dependencies', {
  skip: process.platform !== 'win32',
}, () => {
  const prior = process.env.SystemRoot;
  try {
    const forged = 'C:\\JDC-ATTACKER-CONTROLLED';
    process.env.SystemRoot = forged;
    const expected = resolveSchtasksExecutable();
    assert.match(expected, /^[A-Za-z]:\\.+\\schtasks\.exe$/i);
    assert.notEqual(expected.toLowerCase(), (forged + '\\System32\\schtasks.exe').toLowerCase());
    assert.equal(resolveSchtasksExecutable({ SystemRoot: forged }), expected);
    if (prior === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = prior;
    assert.equal(resolveSchtasksExecutable(), expected);
  } finally {
    if (prior === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = prior;
  }
});

test('Windows task lifecycle launches only the OS-resolved schtasks path', {
  skip: process.platform !== 'win32',
}, async () => {
  const observed = [];
  const expected = resolveSchtasksExecutable();
  await runWindowsScheduledTaskAction('start', 'JDC-TEST-TASK', {
    environment: { SystemRoot: 'C:\\JDC-ATTACKER-CONTROLLED' },
    runExecutable: async (exe, args) => {
      observed.push({ exe, args: [...args] });
      return { stdout: '', stderr: '' };
    },
  });
  assert.deepEqual(observed, [{
    exe: expected,
    args: ['/Run', '/TN', 'JDC-TEST-TASK'],
  }]);
});
