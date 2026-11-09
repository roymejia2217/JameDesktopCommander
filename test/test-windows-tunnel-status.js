import assert from 'node:assert/strict';

import { buildWindowsTunnelTaskXml } from '../dist/platform/windows/tunnel-task.js';
import { getWindowsTunnelStatus } from '../dist/platform/windows/tunnel-status.js';

const taskName = 'Desktop Commander Windows Tunnel';
const tunnelBin = 'C:\\OpenAI\\tunnel-client.exe';
const profileDir = 'C:\\Users\\Roy\\AppData\\Local\\OpenAI\\tunnel-client\\profiles';
const profileName = 'desktop-commander-poc';
const profilePath = profileDir + '\\desktop-commander-poc.yaml';
const healthUrlFile = 'C:\\Users\\Roy\\.local\\state\\tunnel-client\\health\\desktop-commander-poc.url';

const taskXml = buildWindowsTunnelTaskXml({
  author: 'DESKTOP-TEST\\Roy',
  executable: tunnelBin,
  profileDir,
  profileName,
});

const profileText = [
  'control_plane:',
  '  api_key: file:C:\\secrets\\runtime.key',
  'health:',
  `  url_file: '${healthUrlFile.replaceAll('\\', '\\\\')}'`,
  '',
].join('\n');
const healthJson = JSON.stringify({
  locator: {
    kind: 'url_file',
    url_file: healthUrlFile,
    resolved_base_url: 'http://127.0.0.1:53637',
  },
  base_url: 'http://127.0.0.1:53637',
  healthz: { ok: true, status: 200, body: 'live' },
  readyz: { ok: true, status: 200, body: 'ready' },
  control_plane_poll: { value: 1791176905, ok: true },
  result: 'ok',
});

const calls = [];
const status = await getWindowsTunnelStatus(taskName, {
  environment: { SystemRoot: 'C:\\Windows' },
  runExecutable: async (executable, args) => {
    calls.push({ executable, args: [...args] });
    if (executable.endsWith('schtasks.exe')) {
      return { stdout: taskXml, stderr: '' };
    }
    if (args[0] === 'profiles') {
      return {
        stdout: JSON.stringify([{ name: profileName, path: profilePath }]),
        stderr: '',
      };
    }
    if (args[0] === 'health') {
      return { stdout: healthJson, stderr: '' };
    }
    throw new Error('unexpected command');
  },
  readFile: async (filePath) => {
    assert.equal(filePath, profilePath);
    return profileText;
  },
});

assert.deepEqual(calls, [
  {
    executable: 'C:\\Windows\\System32\\schtasks.exe',
    args: ['/Query', '/TN', taskName, '/XML'],
  },
  {
    executable: tunnelBin,
    args: ['profiles', 'list', '--profile-dir', profileDir, '--json'],
  },
  {
    executable: tunnelBin,
    args: [
      'health',
      '--json',
      '--url-file',
      healthUrlFile,
      '--require-control-plane-poll',
    ],
  },
]);
assert.deepEqual(status, {
  taskName,
  task: {
    registered: true,
    executable: tunnelBin,
    profileDir,
    profileName,
  },
  profile: {
    path: profilePath,
    healthUrlFile,
    credentialSource: 'file_reference',
  },
  health: {
    result: 'ok',
    baseUrl: 'http://127.0.0.1:53637',
    live: true,
    ready: true,
    controlPlanePoll: true,
  },
});

assert.doesNotMatch(JSON.stringify(status), /runtime\.key|api_key/i);

// Task Scheduler can hold multiple *types* of actions. One visible Exec
// alongside any other action is not a single-action tunnel registration.
// A read-only overview must not spawn a binary derived from such a task.
for (const [label, injected] of [
  ['COM handler after Exec', '<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>'],
  ['COM handler before Exec', '<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>'],
  ['second Exec', '<Exec><Command>C:/Untrusted/runner.exe</Command></Exec>'],
]) {
  const hostileXml = label === 'COM handler before Exec'
    ? taskXml.replace('<Exec>', injected + '<Exec>')
    : taskXml.replace('</Exec>', '</Exec>' + injected);
  const attempted = [];
  await assert.rejects(
    getWindowsTunnelStatus(taskName, {
      environment: { SystemRoot: 'C:/Windows' },
      runExecutable: async (executable, args) => {
        attempted.push([executable, ...args]);
        if (executable.endsWith('schtasks.exe')) {
          return { stdout: hostileXml, stderr: '' };
        }
        throw new Error('untrusted task-selected binary was executed');
      },
      readFile: async () => {
        throw new Error('untrusted task-selected profile was read');
      },
    }),
    /exactly one Exec action/i,
    label,
  );
  assert.deepEqual(attempted, [
    [calls[0].executable, '/Query', '/TN', taskName, '/XML'],
  ], label);
}

await assert.rejects(
  getWindowsTunnelStatus(taskName, {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (executable, args) => {
      if (executable.endsWith('schtasks.exe')) {
        return { stdout: taskXml, stderr: '' };
      }
      if (args[0] === 'profiles') {
        return { stdout: '[]', stderr: '' };
      }
      throw new Error('unexpected command');
    },
    readFile: async () => profileText,
  }),
  /profile.*not found/i,
);

await assert.rejects(
  getWindowsTunnelStatus(taskName, {
    environment: { SystemRoot: 'C:\\Windows' },
    runExecutable: async (executable, args) => {
      if (executable.endsWith('schtasks.exe')) {
        return { stdout: taskXml, stderr: '' };
      }
      if (args[0] === 'profiles') {
        return {
          stdout: JSON.stringify([{ name: profileName, path: profilePath }]),
          stderr: '',
        };
      }
      if (args[0] === 'health') {
        return { stdout: '{"result":"ok"}', stderr: '' };
      }
      throw new Error('unexpected command');
    },
    readFile: async () => profileText,
  }),
  /health output/i,
);

// An invalid provider YAML must not echo the malformed source or its secret.
await assert.rejects(getWindowsTunnelStatus(taskName, {
  environment: { SystemRoot: 'C:\\Windows' },
  runExecutable: async (executable, args) => {
    if (executable.endsWith('schtasks.exe')) return { stdout: taskXml, stderr: '' };
    if (args[0] === 'profiles') return {
      stdout: JSON.stringify([{ name: profileName, path: profilePath }]), stderr: '',
    };
    throw new Error('Unexpected executable invocation');
  },
  readFile: async () => 'control_plane:\n  api_key: SHOULD_NOT_LEAK: invalid\n',
}), error => {
  assert.equal(error.message, 'Invalid tunnel status profile.');
  assert.doesNotMatch(error.message, /SHOULD_NOT_LEAK/);
  return true;
});

console.log('Windows tunnel status contract: PASS');
