import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildWindowsTunnelTaskXml } from '../dist/platform/windows/tunnel-task.js';
import {
  getWindowsTunnelRegistration, getWindowsTunnelStatus,
} from '../dist/platform/windows/tunnel-status.js';

const taskName = 'Desktop Commander Windows Tunnel';
const attackerExe = 'C:\\Untrusted\\attacker-client.exe';
const xml = buildWindowsTunnelTaskXml({
  author: 'DESKTOP-TEST\\Operator',
  executable: attackerExe, profileDir: 'C:\\Profiles', profileName: 'test',
});

test('task XML cannot authorize a subprocess in registration or health inspection', async () => {
  for (const method of [getWindowsTunnelRegistration, getWindowsTunnelStatus]) {
    const invocations = [];
    await assert.rejects(method(taskName, {
      environment: { SystemRoot: 'C:\\Windows' },
      runExecutable: async (exe, args) => {
        invocations.push({ exe, args: [...args] });
        if (exe.toLowerCase().endsWith('schtasks.exe')) {
          return { stdout: xml, stderr: '' };
        }
        throw new Error('UNTRUSTED_EXECUTABLE_WAS_SELECTED');
      },
    }), /client.*independently.*verified/i);
    assert.equal(invocations.length, 1, 'only trusted schtasks observation may run');
    assert.ok(invocations[0].exe.toLowerCase().endsWith('schtasks.exe'));
  }
});
