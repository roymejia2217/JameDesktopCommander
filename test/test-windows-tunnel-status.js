import assert from 'node:assert/strict';

import { buildWindowsTunnelTaskXml } from '../dist/platform/windows/tunnel-task.js';
import {
  observeWindowsTunnelTaskRegistration, parseWindowsTunnelTaskRegistration,
  parseWindowsTunnelProfileList, parseWindowsTunnelProfileObservation,
  parseWindowsTunnelHealthOutput,
} from '../dist/platform/windows/tunnel-status.js';

const taskName = 'Desktop Commander Windows Tunnel';
const tunnelBin = 'C:\\OpenAI\\tunnel-client.exe';
const profileDir = 'C:\\Users\\Test\\AppData\\Local\\OpenAI\\profiles';
const profileName = 'desktop-commander-poc';
const profilePath = profileDir + '\\desktop-commander-poc.yaml';
const healthUrlFile = 'C:\\Users\\Test\\state\\health.url';
const taskXml = buildWindowsTunnelTaskXml({
  author: 'DESKTOP-TEST\\Operator', executable: tunnelBin,
  profileDir, profileName,
});
const profileText = [
  'control_plane:', '  api_key: file:C:\\secrets\\runtime.key',
  'health:', '  url_file: ' + JSON.stringify(healthUrlFile),
].join('\n');

const healthJson = JSON.stringify({
  base_url: 'http://127.0.0.1:53637',
  healthz: { ok: true }, readyz: { ok: true },
  control_plane_poll: { ok: true }, result: 'ok',
});

assert.deepEqual(parseWindowsTunnelTaskRegistration(taskXml), {
  executable: tunnelBin, profileDir, profileName,
});
assert.equal(parseWindowsTunnelProfileList(JSON.stringify([
  { name: profileName, path: profilePath },
]), profileName), profilePath);
assert.deepEqual(parseWindowsTunnelProfileObservation(profileText), {
  healthUrlFile, credentialSource: 'file_reference',
});
assert.deepEqual(parseWindowsTunnelHealthOutput(healthJson), {
  result: 'ok', baseUrl: 'http://127.0.0.1:53637',
  live: true, ready: true, controlPlanePoll: true,
});

const observed = [];
const registration = await observeWindowsTunnelTaskRegistration(taskName, {
  environment: { SystemRoot: 'C:\\Windows' },
  runExecutable: async (exe, args) => {
    observed.push({ exe, args: [...args] });
    return { stdout: taskXml, stderr: '' };
  },
});
assert.deepEqual(registration, {
  kind: 'untrusted_task_registration_v1',
  registration: { executable: tunnelBin, profileDir, profileName },
});
assert.equal(observed.length, 1);
assert.ok(observed[0].exe.toLowerCase().endsWith('schtasks.exe'));
assert.deepEqual(observed[0].args, ['/Query', '/TN', taskName, '/XML']);
assert.doesNotMatch(JSON.stringify(registration), /runtime\.key|api_key/i);

// A second Exec or COM action invalidates the whole registration.
for (const [label, injected] of [
  ['COM after Exec', '<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>'],
  ['COM before Exec', '<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>'],
  ['second Exec', '<Exec><Command>C:/Untrusted/runner.exe</Command></Exec>'],
]) {
  const hostileXml = label === 'COM before Exec'
    ? taskXml.replace('<Exec>', injected + '<Exec>')
    : taskXml.replace('</Exec>', '</Exec>' + injected);
  const attempted = [];
  await assert.rejects(observeWindowsTunnelTaskRegistration(taskName, {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (exe, args) => {
      attempted.push([exe, ...args]);
      if (exe.toLowerCase().endsWith('schtasks.exe')) {
        return { stdout: hostileXml, stderr: '' };
      }
      throw new Error('UNTRUSTED_EXECUTED');
    },
  }), /exactly one Exec action/i, label);
  assert.equal(attempted.length, 1, label);
  assert.ok(attempted[0][0].toLowerCase().endsWith('schtasks.exe'));
}

assert.throws(
  () => parseWindowsTunnelProfileList('[]', profileName),
  /profile.*not found/i,
);
assert.throws(
  () => parseWindowsTunnelHealthOutput('{"result":"ok"}'),
  /health output/i,
);
assert.throws(
  () => parseWindowsTunnelProfileObservation(
    'control_plane:\n  api_key: SHOULD_NOT_LEAK: invalid\n'),
  error => {
    assert.equal(error.message, 'Invalid tunnel status profile.');
    assert.doesNotMatch(error.message, /SHOULD_NOT_LEAK/);
    return true;
  },
);
assert.throws(
  () => parseWindowsTunnelProfileList('{NOT JSON}', profileName),
  /not valid JSON/,
);
assert.throws(
  () => parseWindowsTunnelHealthOutput('{NOT JSON}'),
  /not valid JSON/,
);
console.log('Windows tunnel task observation / pure parser contract: PASS');
