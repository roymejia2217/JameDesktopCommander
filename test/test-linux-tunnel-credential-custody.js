import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildLinuxTunnelUnit, LINUX_TUNNEL_UNIT, runLinuxTunnelCommand } from '../dist/platform/linux/tunnel-lifecycle.js';

async function withRegisteredFixture(runAssertions) {
  const home = await mkdtemp(path.join(tmpdir(), 'jdc-credential-custody-'));
  const executable = path.join(home, 'tunnel-client');
  const profiles = path.join(home, 'profiles');
  const profilePath = path.join(profiles, 'profile.yaml');
  const secretDirectory = path.join(home, 'credentials');
  const credentialPath = path.join(secretDirectory, 'runtime.key');
  const unitFile = path.join(home, '.config', 'systemd', 'user', LINUX_TUNNEL_UNIT);
  const calls = [];
  try {
    await mkdir(profiles, { mode: 0o700 });
    await mkdir(secretDirectory, { mode: 0o700 });
    await mkdir(path.dirname(unitFile), { recursive: true, mode: 0o700 });
    await writeFile(executable, 'fixture: not executable by mock runner\n', { mode: 0o700 });
    await writeFile(credentialPath, 'synthetic-test-credential-not-real\n', { mode: 0o600 });
    await writeFile(profilePath, 'control_plane:\n  api_key: file:' + credentialPath +
      '\nhealth:\n  url_file: ' + path.join(home, 'health.url') + '\n', { mode: 0o600 });
    await writeFile(unitFile, buildLinuxTunnelUnit(executable, profiles, 'jdc'), { mode: 0o600 });
    const run = async (bin, args) => {
      calls.push([bin, ...args]);
      if (bin === 'systemctl' && args[1] === 'show' && args.includes('--property=FragmentPath')) {
        return 'FragmentPath=' + unitFile +
          '\nDropInPaths=\nLoadState=loaded\nNeedDaemonReload=no\n';
      }
      if (bin === executable && args[0] === 'profiles') {
        return JSON.stringify([{ name: 'jdc', path: profilePath }]);
      }
      if (bin === 'systemctl' && args[1] === 'show-environment') return '';
      throw new Error('Unexpected executable or lifecycle operation in read-only fixture');
    };
    await runAssertions({
      home, executable, profiles, profilePath, secretDirectory,
      credentialPath, unitFile, calls, run,
      deps: { platform: 'linux', home, run },
    });
  } finally {
    await chmod(home, 0o700).catch(() => {});
    await chmod(secretDirectory, 0o700).catch(() => {});
    await rm(home, { recursive: true, force: true });
  }
}

test('Linux checks only registered file-backed credential custody without reading or changing token', {
  skip: process.platform !== 'linux',
}, async () => withRegisteredFixture(async ({ credentialPath, calls, deps }) => {
  const original = await readFile(credentialPath);
  const response = await runLinuxTunnelCommand(['credential-check'], deps);
  assert.equal(response.action, 'credential-check');
  assert.deepEqual(response.credentialCheck, {
    kind: 'registered_credential_custody_v1',
    source: 'file_reference',
    custody: 'verified_point_in_time',
    rotationAuthorized: false,
    remoteAuthentication: 'not_checked',
  });
  assert.deepEqual(await readFile(credentialPath), original);
  assert.ok(!calls.some(x => ['health', 'doctor', 'restart', 'enable', 'disable'].includes(x[1])),
    'Read-only operation must not invoke provider or mutate the user systemd unit');
  assert.doesNotMatch(JSON.stringify(response), /runtime\.key|synthetic-test-credential|profiles/);
}));

test('Linux rejects unsafe file mode, hardlink alias, symlink and mutable parent', {
  skip: process.platform !== 'linux',
}, async () => withRegisteredFixture(async ({ credentialPath, secretDirectory, deps }) => {
  const check = () => runLinuxTunnelCommand(['credential-check'], deps);
  const expectDenied = async () => assert.rejects(check(), (err) => {
    assert.equal(err.message, 'Linux tunnel credential file custody cannot be verified.');
    assert.doesNotMatch(err.message, /runtime\.key|synthetic-test-credential|credential-custody-/);
    return true;
  });
  await chmod(credentialPath, 0o644);
  await expectDenied();
  await chmod(credentialPath, 0o600);

  const alias = credentialPath + '.alias';
  await link(credentialPath, alias);
  await expectDenied();
  await rm(alias);

  await rm(credentialPath);
  const backing = path.join(secretDirectory, 'underlying.key');
  await writeFile(backing, 'synthetic-not-a-real-key', { mode: 0o600 });
  await symlink(backing, credentialPath);
  await expectDenied();
  await rm(credentialPath);
  await writeFile(credentialPath, 'synthetic-test-credential-not-real\n', { mode: 0o600 });

  await chmod(secretDirectory, 0o777);
  await expectDenied();
  await chmod(secretDirectory, 0o700);
  assert.equal((await check()).credentialCheck.custody, 'verified_point_in_time');
}));

test('Linux rejects duplicate options without touching registered files', async () => {
  let called = 0;
  await assert.rejects(
    runLinuxTunnelCommand(['credential-check', '--secret-file', '/tmp/other.key'], {
      platform: 'linux', uid: () => 1000, home: '/tmp',
      run: async () => { called++; return ''; },
    }),
    /no extra arguments/,
  );
  // User manager availability check is permitted; no writable target accepted.
  assert.equal(called, 1);
});

test('Linux reports env references unsupported for file rotation, without reading secrets', {
  skip: process.platform !== 'linux',
}, async () => withRegisteredFixture(async ({ profilePath, deps }) => {
  await writeFile(profilePath,
    'control_plane:\n  api_key: env:CONTROL_PLANE_API_KEY\nhealth:\n  url_file: /tmp/unused\n',
    { mode: 0o600 });
  const response = await runLinuxTunnelCommand(['credential-check'], deps);
  assert.deepEqual(response.credentialCheck, {
    kind: 'registered_credential_custody_v1',
    source: 'environment_reference',
    custody: 'not_checked',
    rotationAuthorized: false,
    remoteAuthentication: 'not_checked',
  });
  assert.doesNotMatch(JSON.stringify(response), /CONTROL_PLANE_API_KEY|\/tmp\/unused/);
}));

test('Linux help advertises read-only credential-check but no rotation mutation', async () => {
  const { runTunnel } = await import('../dist/npm-scripts/tunnel.js');
  const messages = [];
  const original = console.log;
  console.log = (message) => messages.push(String(message));
  try {
    await runTunnel(['--help'], { platform: 'linux' });
  } finally {
    console.log = original;
  }
  assert.match(messages.join('\n'),
    /start \| stop \| restart \| status \| diagnose \| credential-check \| uninstall/);
  assert.doesNotMatch(messages.join('\n'), /credential-rotate|tunnel rotate/i);
});
