import assert from 'node:assert/strict';

import {
  DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME,
  formatWindowsUiBridgeCommandResult,
  runWindowsUiBridgeCommand,
} from '../dist/npm-scripts/ui-bridge.js';

const bridgeExe =
  'C:\\Users\\Roy\\AppData\\Local\\JameDesktopCommander\\ui-bridge\\DesktopCommander.UiBridge.exe';

const calls = [];
const dependencies = {
  platform: 'win32',
  currentUserId: () => 'DESKTOP-TEST\\Roy',
  ensureFile: async (filePath) => {
    calls.push({ kind: 'ensure-file', filePath });
  },
  installTask: async (options) => {
    calls.push({ kind: 'install', options });
    return { stdout: '', stderr: '' };
  },
  startTask: async (taskName) => {
    calls.push({ kind: 'start', taskName });
    return { stdout: '', stderr: '' };
  },
  stopTask: async (taskName) => {
    calls.push({ kind: 'stop', taskName });
    return { stdout: '', stderr: '' };
  },
  uninstallTask: async (taskName) => {
    calls.push({ kind: 'uninstall', taskName });
    return { stdout: '', stderr: '' };
  },
};

const installResult = await runWindowsUiBridgeCommand(
  ['install', '--bridge-exe', bridgeExe],
  dependencies,
);

assert.deepEqual(calls, [
  { kind: 'ensure-file', filePath: bridgeExe },
  {
    kind: 'install',
    options: {
      taskName: DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME,
      replaceExisting: false,
      task: {
        author: 'DESKTOP-TEST\\Roy',
        executable: bridgeExe,
      },
    },
  },
]);
assert.deepEqual(installResult, {
  action: 'install',
  taskName: DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME,
});
assert.equal(
  formatWindowsUiBridgeCommandResult(installResult),
  `Installed Windows UI bridge task "${DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME}".`,
);

calls.length = 0;
await runWindowsUiBridgeCommand(
  ['install', '--bridge-exe', bridgeExe, '--force'],
  dependencies,
);
assert.equal(calls[1].options.replaceExisting, true);

calls.length = 0;
await runWindowsUiBridgeCommand(['start'], dependencies);
await runWindowsUiBridgeCommand(['stop'], dependencies);
await runWindowsUiBridgeCommand(['uninstall'], dependencies);
assert.deepEqual(calls, [
  { kind: 'start', taskName: DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME },
  { kind: 'stop', taskName: DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME },
  { kind: 'uninstall', taskName: DEFAULT_WINDOWS_UI_BRIDGE_TASK_NAME },
]);

await assert.rejects(
  runWindowsUiBridgeCommand(['install'], dependencies),
  /--bridge-exe is required/i,
);
await assert.rejects(
  runWindowsUiBridgeCommand(
    ['install', '--bridge-exe', 'DesktopCommander.UiBridge.exe'],
    dependencies,
  ),
  /absolute Windows path/i,
);
await assert.rejects(
  runWindowsUiBridgeCommand(
    ['install', '--bridge-exe', bridgeExe, '--unknown'],
    dependencies,
  ),
  /unknown option/i,
);
await assert.rejects(
  runWindowsUiBridgeCommand(['start', '--force'], dependencies),
  /does not accept additional arguments/i,
);
await assert.rejects(
  runWindowsUiBridgeCommand(['start'], { ...dependencies, platform: 'linux' }),
  /Windows/i,
);

console.log('Windows UI bridge CLI contract: PASS');
