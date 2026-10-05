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
  statusTunnel: async (taskName) => {
    calls.push({ kind: 'status', taskName });
    return {
      taskName,
      task: {
        registered: true,
        executable: tunnelBin,
        profileDir,
        profileName: 'desktop-commander-poc',
      },
      profile: {
        path: profileDir + '\\desktop-commander-poc.yaml',
        healthUrlFile: 'C:\\health.url',
      },
      health: {
        result: 'ok',
        baseUrl: 'http://127.0.0.1:53637',
        live: true,
        ready: true,
        controlPlanePoll: true,
      },
    };
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
const statusResult = await runWindowsTunnelCommand(['status'], dependencies);
assert.deepEqual(calls, [
  { kind: 'start', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
  { kind: 'stop', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
  { kind: 'uninstall', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
  { kind: 'status', taskName: DEFAULT_WINDOWS_TUNNEL_TASK_NAME },
]);
assert.equal(statusResult.action, 'status');
assert.equal(statusResult.status.health.ready, true);
assert.doesNotMatch(formatWindowsTunnelCommandResult(statusResult), /api_key/i);

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

await assert.rejects(
  runWindowsTunnelCommand(['status', '--extra'], dependencies),
  /does not accept additional arguments/i,
);

console.log('Windows tunnel CLI contract: PASS');
