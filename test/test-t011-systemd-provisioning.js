import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const unit = 'packaging/experimental/linux/systemd/jdc-authority.service';
const account = 'packaging/experimental/linux/sysusers.d/jdc-authority.conf';
const workflow = fs.readFileSync(path.join(repo, '.github/workflows/t011-capability-feasibility.yml'), 'utf8').replace(/\r\n/g, '\n');

test('Linux authority uses standard systemd account and deny-only service configuration', () => {
  const conf = fs.readFileSync(path.join(repo, account), 'utf8');
  assert.match(conf, /^u jdc-authority - "JDC filesystem authority" - \/usr\/sbin\/nologin$/m);
  assert.doesNotMatch(conf, /^m /m, 'do not introduce additional service groups');

  const service = fs.readFileSync(path.join(repo, unit), 'utf8');
  for (const entry of [
    'Type=exec', 'User=jdc-authority', 'Group=jdc-authority',
    'ConditionFileIsExecutable=/usr/libexec/jdc/jdc-authority-service',
    'ExecStart=/usr/libexec/jdc/jdc-authority-service',
    'StateDirectory=jdc-authority', 'StateDirectoryMode=0700',
    'RuntimeDirectory=jdc-authority', 'RuntimeDirectoryMode=0700',
    'ProtectSystem=strict', 'ProtectHome=yes', 'NoNewPrivileges=yes',
    'PrivateTmp=yes', 'PrivateDevices=yes', 'RestrictSUIDSGID=yes',
    'CapabilityBoundingSet=', 'AmbientCapabilities=', 'UMask=0077',
    'StandardOutput=journal', 'StandardError=journal',
    'Restart=no',
  ]) assert.ok(service.split(/\r?\n/).includes(entry), `Missing explicit hardening directive: ${entry}`);
  assert.doesNotMatch(service, /^ConditionPathIsExecutable=/m, 'unsupported systemd condition must never be reintroduced');
  assert.doesNotMatch(service, /^\[Install\]$/m, 'experimental service must not be enabled on boot');
  assert.doesNotMatch(service, /^\s*(?:ExecStartPre|ExecStartPost|ExecStopPost|ReadWritePaths)=/m);
});

test('official systemd validators run within the existing Linux native CI gate', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.doesNotMatch(workflow, /^  linux-service-provisioning:/m);
  assert.ok(workflow.includes('test ! -e /usr/libexec/jdc/jdc-authority-service'),
    'CI must refuse clobbering a pre-existing runner binary');
  assert.ok(workflow.includes('test "${RUNNER_ENVIRONMENT:-}" = "github-hosted"'),
    'CI must be explicitly scoped to an ephemeral runner');
  for (const marker of [
    'cargo +1.91.1 build --locked --manifest-path native/authority-service/Cargo.toml --bin jdc-authority-service',
    'sysusers_file="$(realpath -e -- packaging/experimental/linux/sysusers.d/jdc-authority.conf)"',
    'unit_file="$(realpath -e -- packaging/experimental/linux/systemd/jdc-authority.service)"',
    'systemd-sysusers --dry-run "$sysusers_file"',
    'systemd-analyze verify "$unit_file"',
  ]) assert.ok(workflow.includes(marker), `Missing official CI validation: ${marker}`);
});


test('real admitted MCP socket client must demonstrate systemd activation still denies C4d', () => {
  const acceptance = fs.readFileSync(path.join(repo,
    'test/security/t011-systemd-socket-custody-acceptance.sh'), 'utf8');
  assert.match(acceptance, /SEPARATE_MCP_CLIENT_CONNECT_POSITIVE_NOT_AUTHORIZATION/,
    'retain positive independently provisioned client principal');
  assert.match(acceptance, /client\.sendall\(frame\)/,
    'admitted client must transmit a complete canonical C4d frame');
  assert.match(acceptance, /_SYSTEMD_INVOCATION_ID/,
    'journal evidence must be scoped to the actual activated service invocation');
  assert.match(acceptance, /E_POLICY_UNAVAILABLE/,
    'an admitted C4d client must not produce an authorized broker action');
  assert.match(acceptance, /ExecMainStatus/,
    'the kernel-activated service must exit with the expected failure');
  assert.match(acceptance, /NRestarts/,
    'failing startup must not cause an automatic privileged restart');
});

test('socket denial evidence fallback binds a missing journal invocation tag to the latest OS process', () => {
  const acceptance = fs.readFileSync(path.join(repo,
    'test/security/t011-systemd-socket-custody-acceptance.sh'), 'utf8');
  for (const required of [
    'ExecMainPID',
    'ExecMainStartTimestampMonotonic',
    '_PID=$exec_pid',
    '_UID=$service_uid',
    '_GID=$service_gid',
    '_SYSTEMD_UNIT=$service_name',
    '__MONOTONIC_TIMESTAMP',
    'E_POLICY_UNAVAILABLE',
    'E_IDENTITY_REQUIRED',
  ]) assert.ok(acceptance.includes(required),
    'missing fail-closed correlated denial evidence: ' + required);
});

test('real Linux acceptance independently checks denial by PID and bounded execution window', () => {
  const acceptance = fs.readFileSync(path.join(repo,
    'test/security/t011-systemd-socket-custody-acceptance.sh'), 'utf8');
  assert.match(acceptance, /--argjson maximum "\$exec_exited_us"/,
    'journal acceptance must reject events after the current service process exits');
  assert.match(acceptance, /\.__MONOTONIC_TIMESTAMP \| tonumber\) <= \$maximum/,
    'a reused PID or later event is not evidence for this invocation');
  assert.match(acceptance, /if ! grep -Fxq 'E_POLICY_UNAVAILABLE' <<<"\$pid_journal"/,
    'native acceptance must exercise and REQUIRE process-correlated denial even when the journal invocation tag exists');
  assert.match(acceptance, /T011_SOCKET_DENIAL_CORRELATED_BY_SYSTEMD_PID_NONRELEASE/,
    'the native runner must report positive OS process correlation separately');
});
