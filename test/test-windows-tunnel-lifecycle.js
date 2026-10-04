import assert from 'node:assert/strict';

import {
  buildSchtasksLifecycleArgs,
  installWindowsTunnelTask,
  resolveSchtasksExecutable,
} from '../dist/platform/windows/tunnel-lifecycle.js';

const task = {
  author: 'DESKTOP-TEST\\Roy',
  executable: 'C:\\Program Files\\OpenAI\\tunnel-client.exe',
  profileDir: 'C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles',
  profileName: 'desktop-commander-poc',
};

assert.equal(
  resolveSchtasksExecutable({ SystemRoot: 'C:\\Windows' }),
  'C:\\Windows\\System32\\schtasks.exe',
);

assert.deepEqual(buildSchtasksLifecycleArgs('start', 'Desktop Commander Windows Tunnel'), [
  '/Run',
  '/TN',
  'Desktop Commander Windows Tunnel',
]);
assert.deepEqual(buildSchtasksLifecycleArgs('stop', 'Desktop Commander Windows Tunnel'), [
  '/End',
  '/TN',
  'Desktop Commander Windows Tunnel',
]);
assert.deepEqual(buildSchtasksLifecycleArgs('uninstall', 'Desktop Commander Windows Tunnel'), [
  '/Delete',
  '/TN',
  'Desktop Commander Windows Tunnel',
  '/F',
]);

const calls = [];
const writes = [];
const removals = [];

await installWindowsTunnelTask(
  {
    taskName: 'Desktop Commander Windows Tunnel',
    task,
  },
  {
    environment: { SystemRoot: 'C:\\Windows' },
    makeTempDirectory: async () => 'C:\\Temp\\jdc-task-123',
    writeFile: async (filePath, data) => {
      writes.push({ filePath, data });
    },
    removeDirectory: async (directory) => {
      removals.push(directory);
    },
    runExecutable: async (executable, args) => {
      calls.push({ executable, args: [...args] });
      return { stdout: '', stderr: '' };
    },
  },
);

assert.equal(writes.length, 1);
assert.equal(writes[0].filePath, 'C:\\Temp\\jdc-task-123\\task.xml');
assert.ok(Buffer.isBuffer(writes[0].data));
assert.equal(writes[0].data[0], 0xff);
assert.equal(writes[0].data[1], 0xfe);

assert.deepEqual(calls, [
  {
    executable: 'C:\\Windows\\System32\\schtasks.exe',
    args: [
      '/Create',
      '/TN',
      'Desktop Commander Windows Tunnel',
      '/XML',
      'C:\\Temp\\jdc-task-123\\task.xml',
      '/F',
    ],
  },
]);
assert.deepEqual(removals, ['C:\\Temp\\jdc-task-123']);

const failClosedCalls = [];
await installWindowsTunnelTask(
  {
    taskName: 'Desktop Commander Windows Tunnel',
    task,
    replaceExisting: false,
  },
  {
    environment: { SystemRoot: 'C:\\Windows' },
    makeTempDirectory: async () => 'C:\\Temp\\jdc-task-no-force',
    writeFile: async () => {},
    removeDirectory: async () => {},
    runExecutable: async (executable, args) => {
      failClosedCalls.push({ executable, args: [...args] });
      return { stdout: '', stderr: '' };
    },
  },
);
assert.deepEqual(failClosedCalls[0].args, [
  '/Create',
  '/TN',
  'Desktop Commander Windows Tunnel',
  '/XML',
  'C:\\Temp\\jdc-task-no-force\\task.xml',
]);

const cleanupAfterFailure = [];
await assert.rejects(
  installWindowsTunnelTask(
    {
      taskName: 'Desktop Commander Windows Tunnel',
      task,
    },
    {
      environment: { SystemRoot: 'C:\\Windows' },
      makeTempDirectory: async () => 'C:\\Temp\\jdc-task-failure',
      writeFile: async () => {},
      removeDirectory: async (directory) => {
        cleanupAfterFailure.push(directory);
      },
      runExecutable: async () => {
        throw new Error('synthetic schtasks failure');
      },
    },
  ),
  /synthetic schtasks failure/,
);
assert.deepEqual(cleanupAfterFailure, ['C:\\Temp\\jdc-task-failure']);

console.log('Windows tunnel lifecycle contract: PASS');
