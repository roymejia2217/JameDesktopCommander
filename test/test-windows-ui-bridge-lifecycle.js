import assert from 'node:assert/strict';

import {
  installWindowsUiBridgeTask,
  startWindowsUiBridgeTask,
  stopWindowsUiBridgeTask,
  uninstallWindowsUiBridgeTask,
} from '../dist/platform/windows/ui-bridge-lifecycle.js';

const task = {
  author: 'DESKTOP-TEST\\Roy',
  executable: 'C:\\Users\\Roy\\AppData\\Local\\JameDesktopCommander\\ui-bridge\\DesktopCommander.UiBridge.exe',
};

const calls = [];
const writes = [];
const removals = [];
const dependencies = {
  environment: { SystemRoot: 'C:\\Windows' },
  makeTempDirectory: async () => 'C:\\Temp\\jdc-ui-bridge-task-123',
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
};

await installWindowsUiBridgeTask(
  {
    taskName: 'JameDesktopCommander UI Bridge',
    task,
  },
  dependencies,
);

assert.equal(writes.length, 1);
assert.equal(writes[0].filePath, 'C:\\Temp\\jdc-ui-bridge-task-123\\task.xml');
assert.equal(writes[0].data[0], 0xff);
assert.equal(writes[0].data[1], 0xfe);
assert.deepEqual(calls[0], {
  executable: 'C:\\Windows\\System32\\schtasks.exe',
  args: [
    '/Create',
    '/TN',
    'JameDesktopCommander UI Bridge',
    '/XML',
    'C:\\Temp\\jdc-ui-bridge-task-123\\task.xml',
  ],
});
assert.deepEqual(removals, ['C:\\Temp\\jdc-ui-bridge-task-123']);

calls.length = 0;
await startWindowsUiBridgeTask('JameDesktopCommander UI Bridge', dependencies);
await stopWindowsUiBridgeTask('JameDesktopCommander UI Bridge', dependencies);
await uninstallWindowsUiBridgeTask('JameDesktopCommander UI Bridge', dependencies);
assert.deepEqual(calls, [
  {
    executable: 'C:\\Windows\\System32\\schtasks.exe',
    args: ['/Run', '/TN', 'JameDesktopCommander UI Bridge'],
  },
  {
    executable: 'C:\\Windows\\System32\\schtasks.exe',
    args: ['/End', '/TN', 'JameDesktopCommander UI Bridge'],
  },
  {
    executable: 'C:\\Windows\\System32\\schtasks.exe',
    args: ['/Delete', '/TN', 'JameDesktopCommander UI Bridge', '/F'],
  },
]);

const cleanupAfterFailure = [];
await assert.rejects(
  installWindowsUiBridgeTask(
    {
      taskName: 'JameDesktopCommander UI Bridge',
      task,
    },
    {
      ...dependencies,
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
assert.deepEqual(cleanupAfterFailure, ['C:\\Temp\\jdc-ui-bridge-task-123']);

console.log('Windows UI bridge lifecycle contract: PASS');
