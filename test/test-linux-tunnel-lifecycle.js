import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
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
  const run = async (bin, args) => {
    calls.push([bin, ...args]);
    if (bin === 'systemctl') {
      if (args[1] === 'show') {
        const state = alive ? 'ActiveState=active\nUnitFileState=enabled\n' :
          'ActiveState=inactive\nUnitFileState=disabled\n';
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
    if (args[0] === 'profiles') return JSON.stringify([{ name: 'jdc', path: profilePath }]);
    if (args[0] === 'health') return JSON.stringify({
      result: healthy ? 'ok' : 'degraded',
      healthz: { ok: true }, readyz: { ok: true },
      control_plane_poll: { ok: healthy },
    });
    return '';
  };
  const deps = { platform: 'linux', home, run };
  const file = path.join(home, '.config', 'systemd', 'user', LINUX_TUNNEL_UNIT);
  try {
    await assert.rejects(runLinuxTunnelCommand(['install', '--invalid', '/tmp'], deps), /option/i);
    assert.equal(calls.length, 1, 'Only user-manager availability checked for invalid inputs');
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
    await runLinuxTunnelCommand(['start'], deps);
    assert.ok(calls.some(c => c[0] === 'systemctl' && c[2] === 'enable' && c[3] === '--now'));
    assert.equal((await runLinuxTunnelCommand(['status'], deps)).status.healthy, true);
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
