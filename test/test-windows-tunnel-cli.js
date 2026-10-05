import assert from 'node:assert/strict';

import {
  DEFAULT_WINDOWS_TUNNEL_TASK_NAME,
  formatWindowsTunnelCommandResult,
  runWindowsTunnelCommand,
} from '../dist/npm-scripts/tunnel.js';

const tunnelBin = 'C:\\OpenAI\\tunnel-client.exe';
const profileDir = 'C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles';

const calls = [];
const dependencies = {
  platform: 'win32',
  currentUserId: () => 'DESKTOP-TEST\\Roy',
  runExecutable: async (executable, args) => {
    calls.push({ kind: 'exec', executable, args: [...args] });
    return { stdout: '', stderr: '' };
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

const installResult = await runWindowsTunnelCommand(
  [
    'install',
    '--tunnel-client-bin',
    tunnelBin,
    '--profile-dir',
    profileDir,
    '--profile',
    'desktop-commander-poc',
  ],
  dependencies,
);

assert.deepEqual(calls.slice(0, 2), [
  {
    kind: 'exec',
    executable: tunnelBin,
    args: [
      'doctor',
      '--profile-dir',
      profileDir,
      '--profile',
      'desktop-commander-poc',
      '--explain',
    ],
  },
  {
    kind: 'install',
    options: {
      taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME,
      replaceExisting: false,
      task: {
        author: 'DESKTOP-TEST\\Roy',
        executable: tunnelBin,
        profileDir,
        profileName: 'desktop-commander-poc',
      },
    },
  },
]);
assert.deepEqual(installResult, {
  action: 'install',
  taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME,
});
assert.equal(
  formatWindowsTunnelCommandResult(installResult),
  `Installed Windows tunnel task "${DEFAULT_WINDOWS_TUNNEL_TASK_NAME}".`,
);

calls.length = 0;
await runWindowsTunnelCommand(
  [
    'install',
    '--tunnel-client-bin',
    tunnelBin,
    '--profile-dir',
    profileDir,
    '--profile',
    'desktop-commander-poc',
    '--force',
  ],
  dependencies,
);
assert.equal(calls[1].options.replaceExisting, true);

calls.length = 0;
await runWindowsTunnelCommand(['start'], dependencies);
await runWindowsTunnelCommand(['stop'], dependencies);
await runWindowsTunnelCommand(['uninstall'], dependencies);
assert.deepEqual(calls, [
  { kind: 'start', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
  { kind: 'stop', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
  { kind: 'uninstall', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
]);

await assert.rejects(
  runWindowsTunnelCommand(
    [
      'install',
      '--tunnel-client-bin',
      tunnelBin,
      '--profile-dir',
      profileDir,
      '--profile',
      'desktop-commander-poc',
      '--unknown',
    ],
    dependencies,
  ),
  /unknown option/i,
);

await assert.rejects(
  runWindowsTunnelCommand(
    ['install', '--profile-dir', profileDir, '--profile', 'desktop-commander-poc'],
    dependencies,
  ),
  /--tunnel-client-bin is required/i,
);

await assert.rejects(
  runWindowsTunnelCommand(['start'], { ...dependencies, platform: 'linux' }),
  /Windows/i,
);

console.log('Windows tunnel CLI contract: PASS');
