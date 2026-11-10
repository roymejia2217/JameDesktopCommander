import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { resolveSchtasksExecutable } from '../dist/platform/windows/scheduled-task.js';
import { readWindowsTunnelTaskEvents } from '../dist/platform/windows/tunnel-task-events.js';
import { restartWindowsTunnel } from '../dist/platform/windows/tunnel-restart.js';

const poisonedEnvironment = { SystemRoot: 'C:\\JDC-UNTRUSTED-ROOT' };
const systemDir = path.win32.dirname(resolveSchtasksExecutable(
  process.platform === 'win32' ? poisonedEnvironment : { SystemRoot: 'C:\\Windows' }));
const nativePowerShell = path.win32.join(systemDir, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const nativeTaskkill = path.win32.join(systemDir, 'taskkill.exe');
const success = { stdout: '', stderr: '' };

test('Task Scheduler event observation ignores attacker-controlled SystemRoot', {
  skip: process.platform !== 'win32',
}, async () => {
  let invocation;
  await readWindowsTunnelTaskEvents('Desktop Commander Windows Tunnel', {
    environment: poisonedEnvironment,
    run: async (executable, args) => {
      invocation = { executable, args };
      return { stdout: JSON.stringify({ kind: 'observational_only',
        capped: false, events: [] }), stderr: '' };
    },
  });
  assert.equal(invocation.executable.toLowerCase(), nativePowerShell.toLowerCase());
  assert.equal(invocation.args[3], '-EncodedCommand');
});

test('restart observer and termination use OS-derived native utilities', {
  skip: process.platform !== 'win32',
}, async () => {
  const client = 'C:\\OpenAI\\tunnel-client.exe';
  const profileDir = 'C:\\Profiles';
  const registration = {
    taskName: 'Desktop Commander Windows Tunnel',
    task: { registered: true, executable: client, profileDir, profileName: 'test1' },
    profile: { path: 'C:\\Profiles\\test1.yaml', healthUrlFile: 'C:\\State\\health.url' },
  };
  const root = { processId: 111, parentProcessId: 1, executablePath: client,
    commandLine: '"' + client + '" run --profile-dir "' + profileDir + '" --profile test1',
    creationDate: '2026-11-09T11:00:00.000Z' };
  const nextRoot = { ...root, processId: 222, creationDate: '2026-11-09T11:01:00.000Z' };
  const inventories = [[root], [], [nextRoot]];
  let index = 0;
  const invoked = [];
  const runExecutable = async (executable, args) => {
    invoked.push({ executable, args: [...args] });
    if (args[0] === '-NoLogo') {
      return { stdout: JSON.stringify(inventories[index++]), stderr: '' };
    }
    return success;
  };
  const result = await restartWindowsTunnel('Desktop Commander Windows Tunnel', {
    environment: poisonedEnvironment,
    runExecutable,
    isTaskEnabled: async () => true,
    getRegistration: async () => registration,
    stopTask: async () => success,
    startTask: async () => success,
    sleep: async () => {},
    stopGraceAttempts: 0,
    stopVerifyAttempts: 1,
    startAttempts: 1,
    healthAttempts: 1,
    getStatus: async () => ({ ...registration, health: {
      result: 'ok', baseUrl: 'http://127.0.0.1:1000', live: true,
      ready: true, controlPlanePoll: true,
    } }),
  });
  assert.equal(result.oldRootPid, 111);
  assert.equal(result.newRootPid, 222);
  assert.equal(invoked.length, 4);
  assert.deepEqual(invoked.filter((x) => x.args[0] === '/PID').map((x) => x.executable.toLowerCase()),
    [nativeTaskkill.toLowerCase()]);
  assert.deepEqual(invoked.filter((x) => x.args[0] === '-NoLogo')
    .map((x) => x.executable.toLowerCase()),
    Array(3).fill(nativePowerShell.toLowerCase()));
});
