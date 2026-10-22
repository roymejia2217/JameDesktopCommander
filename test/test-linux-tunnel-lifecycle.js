import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmod, mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  LINUX_TUNNEL_UNIT, buildLinuxTunnelUnit, runLinuxTunnelCommand,
} from '../dist/platform/linux/tunnel-lifecycle.js';

test('Linux unit generation rejects systemd expansion and invalid names', () => {
  const unit = buildLinuxTunnelUnit('/usr/bin/tunnel-client', '/home/test/secure profiles', 'jdc');
  assert.match(unit, /Restart=on-failure/);
  assert.match(unit, /NoNewPrivileges=yes/);
  assert.match(unit, /ExecStart="\/usr\/bin\/tunnel-client" run --profile-dir "\/home\/test\/secure profiles"/);
  assert.ok(!unit.includes('ExecStart=/bin/sh'));
  for (const value of ['/tmp/%n', '/tmp/$HOME', '/tmp/\"inject', 'relative', '/tmp/a\nb']) {
    assert.throws(() => buildLinuxTunnelUnit(value, '/tmp/profiles', 'jdc'));
  }
  assert.throws(() => buildLinuxTunnelUnit('/bin/true', '/tmp/profiles', 'a;evil'));
});

test('Linux tunnel rejects other platforms and root before external calls', async () => {
  let count = 0;
  const dep = { home: '/tmp', run: async () => { count++; return ''; } };
  await assert.rejects(runLinuxTunnelCommand(['start'], { ...dep, platform: 'win32' }), /unprivileged Linux/);
  await assert.rejects(runLinuxTunnelCommand(['start'], { ...dep, platform: 'linux', uid: () => 0 }), /unprivileged Linux/);
  assert.equal(count, 0);
});

test('Linux systemd user lifecycle and actual health are fail-closed and preserve operator stop', {
  skip: process.platform !== 'linux',
}, async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'jdc-linux-tunnel-'));
  const profiles = path.join(home, 'profiles');
  const profilePath = path.join(profiles, 'profile.yaml');
  const profileUrl = path.join(home, 'health.url');
  await mkdir(profiles);
  await writeFile(profilePath, 'health:\n  url_file: ' + profileUrl + '\n');
  const calls = [];
  let alive = true;
  let healthy = true;
  let stopBetweenCheckAndRestart = false;
  let unintendedStarts = 0;
  let injectedDropIn = '';
  let injectedFragment = '';
  let injectedReload = 'no';
  let injectedActivation = null;
  let profileListOverride = null;
  const run = async (bin, args) => {
    calls.push([bin, ...args]);
    if (bin === 'systemctl') {
      if (args[1] === 'show' && args.includes('--property=FragmentPath')) {
        return [
          'FragmentPath=' + injectedFragment,
          'DropInPaths=' + injectedDropIn,
          'LoadState=loaded',
          'NeedDaemonReload=' + injectedReload,
        ].join('\n') + '\n';
      }
      if (args[1] === 'show') {
        const state = injectedActivation ?? (alive ? 'ActiveState=active\nUnitFileState=enabled\n' :
          'ActiveState=inactive\nUnitFileState=disabled\n');
        if (stopBetweenCheckAndRestart) {
          // A separate operator can complete STOP after this read.
          alive = false;
          stopBetweenCheckAndRestart = false;
        }
        return state;
      }
      if (args[1] === 'try-restart') {
        // Model systemd's documented conditional behavior, not a bespoke
        // daemon or a mocked successful restart of an inactive unit.
        if (!alive) return '';
        return '';
      }
      if (args[1] === 'restart') {
        if (!alive) { unintendedStarts++; alive = true; }
        return '';
      }
      return '';
    }
    if (args[0] === 'profiles') return JSON.stringify(profileListOverride ?? [{ name: 'jdc', path: profilePath }]);
    if (args[0] === 'health') return JSON.stringify({
      result: healthy ? 'ok' : 'degraded',
      healthz: { ok: true }, readyz: { ok: true },
      control_plane_poll: { ok: healthy },
    });
    return '';
  };
  const deps = { platform: 'linux', home, run };
  const file = path.join(home, '.config', 'systemd', 'user', LINUX_TUNNEL_UNIT);
  injectedFragment = file;
  try {
    await assert.rejects(runLinuxTunnelCommand(['install', '--invalid', '/tmp'], deps), /option/i);
    assert.equal(calls.length, 1, 'Only user-manager availability checked for invalid inputs');
    // The public CLI preflight verifies the same client/profile contract as
    // install without registering or mutating a systemd unit.
    const doctorResult = await runLinuxTunnelCommand([
      'doctor', '--tunnel-client-bin', process.execPath,
      '--profile-dir', profiles, '--profile', 'jdc',
    ], deps);
    assert.deepEqual(doctorResult, { action: 'doctor', unit: LINUX_TUNNEL_UNIT });
    await assert.rejects(stat(file), { code: 'ENOENT' },
      'Doctor must not install any unit');
    assert.ok(calls.some(c => c[0] === process.execPath && c[1] === 'doctor'),
      'Doctor must call the official tunnel client');
    await assert.rejects(runLinuxTunnelCommand([
      'doctor', '--tunnel-client-bin', process.execPath,
      '--profile-dir', profiles, '--profile', 'invalid;name',
    ], deps), /valid --profile/,
      'Doctor must reject untrusted profile names');
    const configDir = path.join(home, '.config');
    await mkdir(configDir, { mode: 0o700 });
    await chmod(configDir, 0o777);
    await assert.rejects(runLinuxTunnelCommand([
      'install', '--tunnel-client-bin', process.execPath,
      '--profile-dir', profiles, '--profile', 'jdc',
    ], deps), /configuration directory.*writable/i,
    'Installation must reject directories writable by another principal');
    await assert.rejects(stat(file), { code: 'ENOENT' },
      'Unsafe parent must be rejected before installing any unit');
    await chmod(configDir, 0o700);
    await runLinuxTunnelCommand([
      'install', '--tunnel-client-bin', process.execPath,
      '--profile-dir', profiles, '--profile', 'jdc',
    ], deps);
    const saved = await readFile(file, 'utf8');
    assert.match(saved, /Managed by JameDesktopCommander/);
    assert.equal((await stat(file)).mode & 0o077, 0, 'Unit must not be group/world readable');
    await assert.rejects(runLinuxTunnelCommand([
      'install', '--tunnel-client-bin', process.execPath,
      '--profile-dir', profiles, '--profile', 'jdc',
    ], deps), { code: 'EEXIST' }, 'Never overwrite an existing managed unit');
    // A JDC marker and valid ExecStart must not authorize additional
    // directives (including ones that can spawn unrelated commands).
    const originalUnit = await readFile(file, 'utf8');
    await writeFile(file, originalUnit + 'ExecStartPre=/usr/bin/true\n', { mode: 0o600 });
    const beforeMutation = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /differs from the managed template/i);
    await assert.rejects(runLinuxTunnelCommand(['status'], deps),
      /differs from the managed template/i);
    assert.equal(calls.length, beforeMutation + 2,
      'Tampered unit may only trigger non-mutating user-manager preflights');
    await writeFile(file, originalUnit, { mode: 0o600 });
    // The manager can load extra directives even when the JDC .service file
    // matches its byte-for-byte template. All execution routes must deny it.
    injectedDropIn = path.join(home, 'untrusted-override.conf');
    const beforeDropInStart = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /effective systemd unit/i);
    assert.ok(!calls.slice(beforeDropInStart).some(c => c[2] === 'enable'),
      'A manager-loaded drop-in must block service activation');
    injectedDropIn = '';
    injectedReload = 'yes';
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /effective systemd unit/i, 'Stale systemd manager state must fail closed');
    injectedReload = 'no';
    injectedFragment = path.join(home, 'unrelated.service');
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /effective systemd unit/i, 'Unexpected loaded unit fragment must be denied');
    injectedFragment = file;
    const unitParent = path.dirname(file);
    await chmod(unitParent, 0o777);
    const beforeUnsafeStart = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /configuration directory.*writable/i,
      'Start must reject a writable service parent');
    await assert.rejects(runLinuxTunnelCommand(['status'], deps),
      /configuration directory.*writable/i,
      'Status must not claim health for a writable service parent');
    await assert.rejects(runLinuxTunnelCommand(['restart'], deps),
      /configuration directory.*writable/i,
      'Restart must reject a writable service parent');
    assert.ok(!calls.slice(beforeUnsafeStart).some(c =>
      ['enable', 'start', 'restart', 'try-restart'].includes(c[2])),
    'No activating systemd command is permitted on a writable parent');
    // Emergency STOP remains available even if the owner cannot immediately
    // repair the compromised parent permissions.
    assert.equal((await runLinuxTunnelCommand(['stop'], deps)).action, 'stop');
    await assert.rejects(runLinuxTunnelCommand(['uninstall'], deps),
      /configuration directory.*writable/i,
      'Do not unlink units from directories writable by another principal');
    assert.equal((await stat(file)).isFile(), true);
    await chmod(unitParent, 0o700);
    await runLinuxTunnelCommand(['start'], deps);
    assert.ok(calls.some(c => c[0] === 'systemctl' && c[2] === 'enable' && c[3] === '--now'));
    // A manager response containing conflicting activation properties must
    // not authorize status or trigger a restart, even if the first value is
    // the desired active/enabled pair.
    for (const contradictory of [
      'ActiveState=active\nUnitFileState=enabled\nActiveState=inactive\n',
      'ActiveState=active\nUnitFileState=enabled\nUnitFileState=disabled\n',
      'ActiveState=active\nActiveState=active\nUnitFileState=enabled\n',
      'ActiveState=active\nUnitFileState=enabled\nUnknownField=yes\n',
    ]) {
      injectedActivation = contradictory;
      const beforeMalformed = calls.length;
      await assert.rejects(runLinuxTunnelCommand(['status'], deps), /invalid.*state/i);
      await assert.rejects(runLinuxTunnelCommand(['restart'], deps), /invalid.*state/i);
      assert.ok(!calls.slice(beforeMalformed).some(c => c[2] === 'try-restart'),
        'Malformed state must not restart the service');
    }
    injectedActivation = null;
    injectedDropIn = path.join(home, 'untrusted-override.conf');
    await assert.rejects(runLinuxTunnelCommand(['status'], deps),
      /effective systemd unit/i);
    const beforeDropInRestart = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['restart'], deps),
      /effective systemd unit/i);
    assert.ok(!calls.slice(beforeDropInRestart).some(c => c[2] === 'try-restart'),
      'Drop-in must block restart before any executable transition');
    injectedDropIn = '';
    assert.equal((await runLinuxTunnelCommand(['status'], deps)).status.healthy, true);
    // A client reporting two entries for one configured profile is ambiguous.
    // Do not select the first entry and claim authenticated readiness.
    for (const duplicate of [
      [{ name: 'jdc', path: profilePath }, { name: 'jdc', path: profilePath }],
      [{ name: 'jdc', path: profilePath },
        { name: 'jdc', path: path.join(home, 'alternate-profile.yaml') }],
    ]) {
      profileListOverride = duplicate;
      const beforeAmbiguous = calls.length;
      await assert.rejects(runLinuxTunnelCommand(['status'], deps),
        /profile.*ambiguous/i, 'Duplicate profile names must be rejected');
      assert.ok(!calls.slice(beforeAmbiguous).some(c => c[1] === 'health'),
        'Ambiguous profiles must not trigger a health check');
    }
    profileListOverride = null;
    const beforeRestart = calls.length;
    assert.equal((await runLinuxTunnelCommand(['restart'], deps)).action, 'restart');
    assert.ok(calls.slice(beforeRestart).some(c =>
      c[0] === 'systemctl' && c[2] === 'try-restart' && c[3] === LINUX_TUNNEL_UNIT),
      'Use systemd try-restart to preserve STOP under interleaving');
    stopBetweenCheckAndRestart = true;
    const beforeInterleaved = calls.length;
    assert.equal((await runLinuxTunnelCommand(['restart'], deps)).action, 'restart');
    assert.ok(calls.slice(beforeInterleaved).some(c => c[2] === 'try-restart'),
      'Interleaved STOP must reach conditional restart only');
    assert.equal(unintendedStarts, 0, 'Interleaved STOP may not revive the tunnel');
    assert.equal(alive, false, 'Stop between state check and restart must remain effective');
    alive = true;
    healthy = false;
    assert.equal((await runLinuxTunnelCommand(['status'], deps)).status.healthy, false);
    await assert.rejects(runLinuxTunnelCommand(['restart', '--force'], deps),
      /no extra arguments/, 'Unrecognized restart options must fail closed');
    alive = false;
    assert.equal((await runLinuxTunnelCommand(['status'], deps)).status.active, false);
    const beforeRejectedRestart = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['restart'], deps), /enabled, active/);
    assert.ok(!calls.slice(beforeRejectedRestart).some(c => c[2] === 'try-restart' || c[2] === 'restart'),
      'Inactive service must not restart');
    await runLinuxTunnelCommand(['stop'], deps);
    const afterStop = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['restart'], deps), /enabled, active/);
    assert.ok(!calls.slice(afterStop).some(c => c[2] === 'try-restart' || c[2] === 'restart'),
      'Explicit operator stop must persist');
    assert.ok(calls.some(c => c[0] === 'systemctl' && c[2] === 'disable' && c[3] === '--now'));
    await runLinuxTunnelCommand(['uninstall'], deps);
    await assert.rejects(stat(file), { code: 'ENOENT' });
    assert.ok(calls.filter(c => c[0] === 'systemctl' && c[2] === 'daemon-reload').length >= 2);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('Linux recovery disables and removes an owned altered JDC unit without running it', {
  skip: process.platform !== 'linux',
}, async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'jdc-linux-recovery-'));
  const unitFile = path.join(home, '.config', 'systemd', 'user', LINUX_TUNNEL_UNIT);
  const calls = [];
  const run = async (bin, args) => {
    calls.push([bin, ...args]);
    return '';
  };
  const deps = { home, platform: 'linux', run };
  try {
    await mkdir(path.dirname(unitFile), { recursive: true, mode: 0o700 });
    const clean = buildLinuxTunnelUnit('/usr/bin/tunnel-client', '/tmp/jdc-ci-profile', 'ci');
    await writeFile(unitFile, clean + 'ExecStartPre=/usr/bin/true\n', { mode: 0o600 });
    await assert.rejects(runLinuxTunnelCommand(['start'], deps),
      /differs from the managed template/);
    await assert.rejects(runLinuxTunnelCommand(['restart'], deps),
      /differs from the managed template/);
    await assert.rejects(runLinuxTunnelCommand(['status'], deps),
      /differs from the managed template/);
    const beforeRecovery = calls.length;
    assert.deepEqual(await runLinuxTunnelCommand(['stop'], deps),
      { action: 'stop', unit: LINUX_TUNNEL_UNIT });
    assert.deepEqual(await runLinuxTunnelCommand(['uninstall'], deps),
      { action: 'uninstall', unit: LINUX_TUNNEL_UNIT });
    await assert.rejects(stat(unitFile), { code: 'ENOENT' });
    const recovery = calls.slice(beforeRecovery);
    assert.equal(recovery.filter(c =>
      c[0] === 'systemctl' && c[2] === 'disable' && c[3] === '--now').length, 2);
    assert.ok(!recovery.some(c => ['enable', 'start', 'restart', 'try-restart'].includes(c[2])),
      'Recovery must not execute an altered unit');
    await writeFile(unitFile, '# unrelated user-owned service\n', { mode: 0o600 });
    const beforeUnrelated = calls.length;
    await assert.rejects(runLinuxTunnelCommand(['uninstall'], deps),
      /not JDC-managed/, 'Never delete an unrelated unit');
    assert.equal(calls.length, beforeUnrelated + 1,
      'Unrelated units permit only non-mutating user-manager preflight');
    assert.equal((await stat(unitFile)).isFile(), true);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('Linux no user systemd session must fail before writing a service', {
  skip: process.platform !== 'linux',
}, async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'jdc-linux-no-bus-'));
  try {
    await assert.rejects(runLinuxTunnelCommand(['install'], {
      home, platform: 'linux',
      run: async () => { throw new Error('User bus unavailable'); },
    }), /User bus unavailable/);
    await assert.rejects(stat(path.join(home, '.config')), { code: 'ENOENT' });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
