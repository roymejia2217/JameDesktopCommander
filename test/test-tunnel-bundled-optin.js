import test from 'node:test';
import assert from 'node:assert/strict';
import { expandBundledTunnelArguments } from '../dist/platform/tunnel-bundled.js';

const baseArgs = ['install', '--profile-dir', '/data/profiles', '--profile', 'my-tunnel'];

test('bundled tunnel selection is explicit and preserves old CLI options', () => {
  assert.deepEqual(expandBundledTunnelArguments(baseArgs, 'linux', '/opt/jame-desktop-commander'), baseArgs);
  const linux = expandBundledTunnelArguments([...baseArgs, '--bundled'], 'linux', '/opt/jame-desktop-commander');
  assert.deepEqual(linux, [...baseArgs, '--tunnel-client-bin', '/opt/jame-desktop-commander/tools/tunnel-client/tunnel-client']);
  const windows = expandBundledTunnelArguments(['install', '--bundled'], 'win32', 'C:\\JDC');
  assert.deepEqual(windows, ['install', '--tunnel-client-bin', 'C:\\JDC\\tools\\tunnel-client\\tunnel-client.exe']);
});

test('bundled mode is permitted for Linux doctor only as a read-only action', () => {
  const result = expandBundledTunnelArguments(['doctor', '--bundled'], 'linux', '/opt/jame-desktop-commander');
  assert.deepEqual(result, ['doctor', '--tunnel-client-bin', '/opt/jame-desktop-commander/tools/tunnel-client/tunnel-client']);
});

test('ambiguous or implicit bundled selection fails closed', () => {
  const invalid = [
    ['start', '--bundled'],
    ['restart', '--bundled'],
    ['install', '--bundled', '--bundled'],
    ['install', '--bundled', '--tunnel-client-bin', '/tmp/untrusted'],
  ];
  for (const args of invalid) {
    assert.throws(() => expandBundledTunnelArguments(args, 'linux', '/opt/jame-desktop-commander'), /bundled|conflict/i);
  }
  assert.throws(() => expandBundledTunnelArguments(['doctor', '--bundled'], 'win32', 'C:\\JDC'), /bundled/i);
  assert.throws(() => expandBundledTunnelArguments(['install', '--bundled'], 'darwin', '/tmp/app'), /Unsupported/i);
});

test('Windows install with --bundled runs doctor before scheduling, never starts a task', async () => {
  const { runTunnel } = await import('../dist/npm-scripts/tunnel.js');
  const calls = [];
  const deps = {
    platform: 'win32',
    currentUserId: () => 'TEST\\user',
    runExecutable: async (executable, args) => {
      calls.push({ kind: 'doctor', executable, args });
      return { stdout: '', stderr: '' };
    },
    installTask: async (options) => { calls.push({ kind: 'install', options }); return { stdout: '', stderr: '' }; },
    installRestartSupervisorTask: async (options) => { calls.push({ kind: 'supervisor', options }); return { stdout: '', stderr: '' }; },
    nodeExecutable: () => 'C:\\Program Files\\nodejs\\node.exe',
    restartWorkerScript: () => 'C:\\JDC\\worker.js',
  };
  await runTunnel(['install', '--bundled', '--profile-dir', 'C:\\Private\\profiles', '--profile', 'test'], deps);
  assert.deepEqual(calls.map(({ kind }) => kind), ['doctor', 'install', 'supervisor']);
  assert.match(calls[0].executable, /tools\\tunnel-client\\tunnel-client\.exe$/);
  assert.deepEqual(calls[0].args, ['doctor', '--profile-dir', 'C:\\Private\\profiles', '--profile', 'test', '--explain']);
  assert.equal(calls[1].options.replaceExisting, false);
});
