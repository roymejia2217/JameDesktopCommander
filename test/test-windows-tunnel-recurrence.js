import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildWindowsTunnelTaskXml,
} from '../dist/platform/windows/tunnel-task.js';
import {
  parseWindowsTunnelTaskEnabled,
} from '../dist/platform/windows/tunnel-status.js';
import {
  startWindowsTunnelTask,
  stopWindowsTunnelTask,
} from '../dist/platform/windows/tunnel-lifecycle.js';
import { restartWindowsTunnel } from '../dist/platform/windows/tunnel-restart.js';
import { runWindowsTunnelCommand } from '../dist/npm-scripts/tunnel.js';

const taskName = 'Desktop Commander Windows Tunnel';
const task = {
  author: 'TEST\\Operator',
  executable: 'C:\\Program Files\\OpenAI\\tunnel-client.exe',
  profileDir: 'C:\\profiles',
  profileName: 'testing',
};
const rootXml = buildWindowsTunnelTaskXml(task);

test('an opt-in boot trigger repeats without a parallel process', () => {
  const xml = buildWindowsTunnelTaskXml({ ...task, recoveryIntervalMinutes: 5 });
  assert.match(xml, /<BootTrigger>[\s\S]*<Repetition>[\s\S]*<Interval>PT5M<\/Interval>[\s\S]*<\/Repetition>[\s\S]*<\/BootTrigger>/);
  assert.match(xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
  assert.doesNotMatch(rootXml, /<Repetition>/);
});

test('Task Scheduler enabled state is explicit, parsed, and fails closed on ambiguity', () => {
  assert.equal(parseWindowsTunnelTaskEnabled(rootXml), true);
  const disabled = rootXml.replace('<Enabled>true</Enabled>\r\n    <Hidden>',
    '<Enabled>false</Enabled>\r\n    <Hidden>');
  assert.equal(parseWindowsTunnelTaskEnabled(disabled), false);
  assert.throws(() => parseWindowsTunnelTaskEnabled(
    rootXml.replace('    <Enabled>true</Enabled>\r\n    <Hidden>',
      '    <Hidden>')), /enabled state/i);
  assert.throws(() => parseWindowsTunnelTaskEnabled(
    '<Task><Settings><Enabled>maybe</Enabled></Settings></Task>'), /enabled state/i);
});

test('operator stop disables first, then ends; operator start enables then starts', async () => {
  const calls = [];
  const deps = {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (_exe, args) => {
      calls.push(args);
      return { stdout: '', stderr: '' };
    },
  };
  await stopWindowsTunnelTask(taskName, deps);
  await startWindowsTunnelTask(taskName, deps);
  assert.deepEqual(calls, [
    ['/Change', '/TN', taskName, '/DISABLE'],
    ['/End', '/TN', taskName],
    ['/Change', '/TN', taskName, '/ENABLE'],
    ['/Run', '/TN', taskName],
  ]);
});

test('if task disabling fails, no process termination follows', async () => {
  const calls = [];
  await assert.rejects(stopWindowsTunnelTask(taskName, {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (_exe, args) => {
      calls.push(args);
      throw new Error('ACL denies task disable');
    },
  }), /ACL denies/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].at(-1), '/DISABLE');
});

test('if enabling fails, no process start follows', async () => {
  const calls = [];
  await assert.rejects(startWindowsTunnelTask(taskName, {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (_exe, args) => {
      calls.push(args);
      throw new Error('ACL denies task enable');
    },
  }), /ACL denies/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].at(-1), '/ENABLE');
});

test('the external restart worker refuses operator-disabled tasks', async () => {
  let touched = false;
  await assert.rejects(restartWindowsTunnel(taskName, {
    isTaskEnabled: async () => false,
    getRegistration: async () => { touched = true; throw new Error('unexpected'); },
  }), /operator-disabled/i);
  assert.equal(touched, false);
});

test('revocation during a pending restart stops before any start action', async () => {
  let probes = 0;
  let started = false;
  const registration = {
    taskName,
    task: {
      registered: true, executable: task.executable,
      profileDir: task.profileDir, profileName: task.profileName,
    },
    profile: { path: 'C:\\profiles\\testing.yml', healthUrlFile: 'C:\\health.url' },
  };
  await assert.rejects(restartWindowsTunnel(taskName, {
    isTaskEnabled: async () => ++probes === 1,
    getRegistration: async () => registration,
    listProcesses: async () => [],
    startTask: async () => { started = true; return { stdout: '', stderr: '' }; },
  }), /disabled while restart was pending/i);
  assert.equal(probes, 2);
  assert.equal(started, false);
});

test('install requires explicit opt-in and does not force-replace existing tasks', async () => {
  const installed = [];
  const dependencies = {
    platform: 'win32',
    currentUserId: () => 'TEST\\Operator',
    nodeExecutable: () => 'C:\\node.exe',
    restartWorkerScript: () => 'C:\\worker.js',
    runExecutable: async () => ({ stdout: '', stderr: '' }),
    installTask: async (data) => {
      installed.push(data);
      return { stdout: '', stderr: '' };
    },
    installRestartSupervisorTask: async () => ({ stdout: '', stderr: '' }),
  };
  await runWindowsTunnelCommand([
    'install', '--tunnel-client-bin', task.executable,
    '--profile-dir', task.profileDir, '--profile', task.profileName,
    '--recover-on-exit',
  ], dependencies);
  assert.equal(installed[0].replaceExisting, false);
  assert.equal(installed[0].task.recoveryIntervalMinutes, 5);
  await assert.rejects(runWindowsTunnelCommand([
    'install', '--tunnel-client-bin', task.executable,
    '--profile-dir', task.profileDir, '--profile', task.profileName,
    '--recover-on-exit', '--recover-on-exit',
  ], dependencies), /only once/i);
});
