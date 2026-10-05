import assert from 'node:assert/strict';

import {
  buildWindowsTunnelRestartSupervisorTaskXml,
} from '../dist/platform/windows/tunnel-restart-supervisor-task.js';
import {
  buildWindowsProcessInventoryPowerShell,
  captureOwnedTunnelProcessTree,
  restartWindowsTunnel,
} from '../dist/platform/windows/tunnel-restart.js';

const taskName = 'Desktop Commander Windows Tunnel';
const tunnelBin = 'C:\\OpenAI\\tunnel-client.exe';

const processInventoryScript = buildWindowsProcessInventoryPowerShell();
assert.match(processInventoryScript, /Get-CimInstance Win32_Process/);
assert.match(processInventoryScript, /\[pscustomobject\]@\{\r?\n/);
assert.doesNotMatch(processInventoryScript, /@\{;/);
const profileDir = 'C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles';

const supervisorXml = buildWindowsTunnelRestartSupervisorTaskXml({
  author: 'DESKTOP-TEST\\Roy',
  nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
  workerScript: 'E:\\JameDesktopCommander\\dist\\npm-scripts\\tunnel-restart-worker.js',
  tunnelTaskName: taskName,
});
assert.match(supervisorXml, /<LogonType>S4U<\/LogonType>/);
assert.match(supervisorXml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
assert.match(supervisorXml, /<Triggers\s*\/>/);
assert.match(supervisorXml, /node\.exe/);
assert.match(supervisorXml, /tunnel-restart-worker\.js/);
assert.match(supervisorXml, /Desktop Commander Windows Tunnel/);

const registration = {
  taskName,
  task: {
    registered: true,
    executable: tunnelBin,
    profileDir,
    profileName: 'desktop-commander-poc',
  },
  profile: {
    path: profileDir + '\\desktop-commander-poc.yaml',
    healthUrlFile: 'C:\\state\\health.url',
  },
};

const root = {
  processId: 100,
  parentProcessId: 50,
  executablePath: tunnelBin,
  commandLine:
    '"C:\\OpenAI\\tunnel-client.exe" run --profile-dir "' +
    profileDir +
    '" --profile desktop-commander-poc',
  creationDate: '2026-10-05T10:00:00.000Z',
};
const child = {
  processId: 200,
  parentProcessId: 100,
  executablePath: 'C:\\Program Files\\nodejs\\node.exe',
  commandLine: '"C:\\Program Files\\nodejs\\node.exe" "E:\\JameDesktopCommander\\dist\\index.js"',
  creationDate: '2026-10-05T10:00:01.000Z',
};
const grandchild = {
  processId: 300,
  parentProcessId: 200,
  executablePath: 'C:\\Windows\\System32\\cmd.exe',
  commandLine: 'cmd.exe /c test',
  creationDate: '2026-10-05T10:00:02.000Z',
};
const unrelated = {
  processId: 999,
  parentProcessId: 1,
  executablePath: tunnelBin,
  commandLine: '"C:\\OpenAI\\tunnel-client.exe" doctor --help',
  creationDate: '2026-10-05T09:00:00.000Z',
};

const captured = captureOwnedTunnelProcessTree(
  registration,
  [root, child, grandchild, unrelated],
);
assert.equal(captured.root?.processId, 100);
assert.deepEqual(captured.descendants.map((process) => process.processId), [200, 300]);

const duplicateRoot = { ...root, processId: 101, creationDate: '2026-10-05T10:00:03.000Z' };
assert.throws(
  () => captureOwnedTunnelProcessTree(registration, [root, duplicateRoot]),
  /multiple tunnel-client processes/i,
);

const newRoot = {
  ...root,
  processId: 400,
  creationDate: '2026-10-05T10:01:00.000Z',
};
const newChild = {
  ...child,
  processId: 500,
  parentProcessId: 400,
  creationDate: '2026-10-05T10:01:01.000Z',
};

const snapshots = [
  [root, child, grandchild],
  [child, grandchild],
  [],
  [newRoot, newChild],
];
const calls = [];
let snapshotIndex = 0;
let healthAttempt = 0;

const result = await restartWindowsTunnel(taskName, {
  getRegistration: async () => registration,
  listProcesses: async () => snapshots[Math.min(snapshotIndex++, snapshots.length - 1)],
  stopTask: async (name) => {
    calls.push({ kind: 'stop', name });
    return { stdout: '', stderr: '' };
  },
  startTask: async (name) => {
    calls.push({ kind: 'start', name });
    return { stdout: '', stderr: '' };
  },
  terminateProcessTree: async (pid) => {
    calls.push({ kind: 'taskkill', pid });
    return { stdout: '', stderr: '' };
  },
  getStatus: async () => {
    healthAttempt += 1;
    if (healthAttempt === 1) {
      throw new Error('not ready yet');
    }
    return {
      ...registration,
      health: {
        result: 'ok',
        baseUrl: 'http://127.0.0.1:60000',
        live: true,
        ready: true,
        controlPlanePoll: true,
      },
    };
  },
  sleep: async () => {},
  stopGraceAttempts: 1,
  startAttempts: 2,
  healthAttempts: 2,
});

assert.deepEqual(calls, [
  { kind: 'stop', name: taskName },
  { kind: 'taskkill', pid: 200 },
  { kind: 'start', name: taskName },
]);
assert.equal(result.oldRootPid, 100);
assert.equal(result.newRootPid, 400);
assert.equal(result.health.ready, true);
assert.equal(result.health.controlPlanePoll, true);

console.log('Windows tunnel restart contract: PASS');
