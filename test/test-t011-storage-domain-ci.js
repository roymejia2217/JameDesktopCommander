import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const native = fs.readFileSync(path.join(repo,
  '.github/workflows/t011-capability-feasibility.yml'), 'utf8').replace(/\r\n/g, '\n');
const linux = path.join(repo, 'test/security/t011-linux-storage-domain-acceptance.sh');
const windows = path.join(repo, 'test/security/t011-windows-storage-domain-acceptance.ps1');

test('both OS-backed storage-domain acceptances are mandatory native CI steps', () => {
  for (const [target, script, command] of [
    ['linux-x64', linux, 'bash test/security/t011-linux-storage-domain-acceptance.sh'],
    ['win32-x64', windows, 'pwsh -NoProfile -File test/security/t011-windows-storage-domain-acceptance.ps1'],
  ]) {
    assert.ok(fs.existsSync(script), `missing ${script}`);
    assert.match(native, new RegExp(`if: matrix.target == '${target}'\\n        run: ${command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  }
});

test('positive same-volume hardlink, genuine cross-volume rejection, byte preservation and fail-closed runner gates', () => {
  const l = fs.readFileSync(linux, 'utf8');
  const w = fs.readFileSync(windows, 'utf8');
  for (const input of [l, w]) {
    assert.match(input, /RUNNER_ENVIRONMENT/);
    assert.match(input, /SAME_VOLUME_HARDLINK_PASS/);
    assert.match(input, /CROSS_VOLUME_HARDLINK_DENIED/);
    assert.match(input, /EXTERIOR_BYTES_UNCHANGED/);
    assert.doesNotMatch(input, /continue-on-error|exit 0.*denied/);
  }
  assert.match(l, /mount -t tmpfs/);
  assert.match(l, /sudo -n -u nobody/);
  assert.match(w, /diskpart\.exe/);
  assert.match(w, /New-LocalUser/);
});

test('CI principals and native probe argument binding preserve positive controls', () => {
  const l = fs.readFileSync(linux, 'utf8');
  const w = fs.readFileSync(windows, 'utf8');
  assert.match(l, /sudo -n -u nobody -- sha256sum "\$outside_file"/);
  assert.match(l, /sudo -n stat -c %d:%i "\$outside_file"/);
  assert.doesNotMatch(w, /\[string\[\]\]\s*\$args\b/);
  assert.match(w, /function Invoke-CIUser\([^\n]*\$probeArgs\)/);
  assert.match(w, /-ArgumentList \$probeArgs\b/);
  assert.match(w, /function Require-UserSuccess\([^\n]*\$probeArgs\)/);
  assert.match(w, /function Require-UserDenial\([^\n]*\$probeArgs\)/);
});

test('Linux administrator bind mount exposes a real outside object, not a second hard link', () => {
  const l = fs.readFileSync(linux, 'utf8');
  assert.match(l, /sudo -n mount --bind "\$outside_file" "\$bind_alias"/);
  assert.match(l, /sudo -n -u jdc-authority -- cat "\$outside_file"/);
  assert.match(l, /sudo -n -u jdc-authority -- cat "\$bind_alias"/);
  assert.match(l, /sudo -n stat -c %d:%i "\$bind_alias"/);
  assert.match(l, /findmnt --kernel --mountpoint "\$bind_alias"/);
  assert.match(l, /sudo -n umount -- "\$bind_alias"/);
  assert.match(l, /T011_STORAGE_ADMIN_BIND_ALIAS_EXPOSES_OUTSIDE_OBJECT_NONRELEASE/);
});

test('Linux openat2 uses root FD and NO_XDEV to deny a genuine file bind-mount alias', () => {
  const probe = path.join(repo, 'native/authority-service/examples/linux_openat2_mount_probe.rs');
  assert.ok(fs.existsSync(probe), 'missing real kernel openat2 probe');
  const src = fs.readFileSync(probe, 'utf8');
  const l = fs.readFileSync(linux, 'utf8');
  assert.match(src, /rustix::fs::\{openat2,/);
  assert.match(src, /ResolveFlags::NO_XDEV/);
  assert.match(src, /ResolveFlags::BENEATH/);
  assert.match(src, /libc::EXDEV/);
  assert.match(l, /linux_openat2_mount_probe/);
  assert.match(l, /sudo -n install -o jdc-authority -g jdc-authority -m 0500/);
  assert.match(l, /sha256sum "\$probe_path"/);
  assert.match(l, /service\.bin allow/);
  assert.match(l, /admin-import\.bin deny-exdev/);
  assert.match(l, /stat -c %h "\$outside_file"/);
  assert.match(l, /T011_STORAGE_OPENAT2_NO_XDEV_DENIES_BIND_ALIAS_NONRELEASE/);
});

// A failed hard-link operation is not enough: administrative cross-volume
// controls must identify the Windows kernel's ERROR_NOT_SAME_DEVICE (17).
test('Windows admin cross-volume denials must prove the exact OS error', () => {
  const script = fs.readFileSync(windows, 'utf8');
  const probe = fs.readFileSync(path.join(repo,
    'native/authority-store/examples/custody_attacker.rs'), 'utf8');
  assert.match(script, /E_HARDLINK_OS_ERROR_17/);
  assert.match(script, /RedirectStandardError/);
  assert.match(probe, /E_HARDLINK_OS_ERROR_/);
});
