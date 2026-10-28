import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(
  path.join(repo, '.github/workflows/t011-capability-feasibility.yml'), 'utf8',
).replace(/\r\n/g, '\n');

test('cross-principal proof is inside the existing governed Linux native job', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.match(workflow, /^          - runner: ubuntu-24\.04\n            target: linux-x64$/m);
  assert.doesNotMatch(workflow, /^  linux-custody-acceptance:/m,
    'a detached optional job must not be mistaken for an already-governed native gate');

  for (const [name, command] of [
    ['Build test-only dedicated identity probe on Linux',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-service/Cargo.toml'],
    ['Build test-only transactional store fixture on Linux',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml'],
    ['Lint Linux cross-principal acceptance fixture',
      'shellcheck --severity=warning test/security/t011-linux-custody-acceptance.sh && bash -n test/security/t011-linux-custody-acceptance.sh'],
    ['Prove Linux distinct-principal custody and reject database rollback',
      'bash test/security/t011-linux-custody-acceptance.sh'],
  ]) {
    assert.ok(workflow.includes(`      - name: ${name}\n        if: matrix.target == 'linux-x64'\n        run: ${command}`),
      `Linux-only native control missing or conditional check removed: ${name}`);
  }
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-custody-acceptance.sh'), 'utf8',
  );
  for (const expression of [
    /set -euo pipefail/, /RUNNER_ENVIRONMENT/, /getent passwd jdc-authority/,
    /sudo -n -u nobody/, /sudo -n -u jdc-authority/,
    /expect_denied replay/, /sha256sum/, /verify-2/,
    /setpriv --reuid/, /E_CUSTODY_GROUP_INJECTION_NOT_PROVEN/,
    /E_CUSTODY_SUPPLEMENTARY_GROUP_ACCEPTED/,
  ]) {
    assert.match(script, expression);
  }
});

test('Linux custody positive and adversarial identities run under verified kernel NNP', () => {
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-custody-acceptance.sh'), 'utf8',
  );
  assert.match(script, /sudo -n -u jdc-authority -- setpriv --no-new-privs -- "\$identity_probe"/);
  assert.match(script, /sudo -n -u jdc-authority -- setpriv --no-new-privs -- awk/);
  assert.match(script, /E_CUSTODY_NO_NEW_PRIVS_NOT_PROVEN/);
  assert.match(script, /setpriv --reuid "\$service_uid" --regid "\$service_gid" --groups "\$service_gid,\$attacker_gid" --no-new-privs -- "\$identity_probe"/);
  assert.match(script, /if sudo -n -u nobody -- setpriv --no-new-privs -- "\$identity_probe"; then/);
  assert.match(script, /expect_denied identity sudo -n -u nobody -- setpriv --no-new-privs -- "\$identity_probe"/);
  assert.doesNotMatch(script, /^sudo -n -u jdc-authority -- "\$identity_probe"$/m);
});

test('root-admin policy SQLite-file candidate requires real OS-anchored principal custody', () => {
  for (const [name, cmd] of [
    ['Lint Linux admin-owned policy-file custody acceptance',
      'shellcheck --severity=warning test/security/t011-linux-admin-policy-file-acceptance.sh && bash -n test/security/t011-linux-admin-policy-file-acceptance.sh'],
    ['Prove admin-owned policy-file inode custody under Linux service identity',
      'bash test/security/t011-linux-admin-policy-file-acceptance.sh'],
  ]) {
    assert.ok(workflow.includes(`      - name: ${name}\n        if: matrix.target == 'linux-x64'\n        run: ${cmd}`));
  }
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-admin-policy-file-acceptance.sh'), 'utf8',
  );
  for (const expression of [
    /RUNNER_ENVIRONMENT/, /custody_fixture/, /NoNewPrivs/, /setpriv --no-new-privs/,
    /sudo -n chown jdc-authority:jdc-authority/, /sudo -n chmod 0660/,
    /sudo -n ln -- "\$policy" "\$alias"/, /sudo -n ln -s -- "\$source_file" "\$policy"/,
    /verdict DENIED sudo -n -u jdc-mcp-client/,
    /verdict CANDIDATE sudo -n -u jdc-authority/,
    /verdict VERIFIED_BYTES sudo -n -u jdc-authority -- setpriv --no-new-privs -- "\$probe" policy-snapshot/,
    /init-policy-bytes/, /write-policy-anchor/, /write-policy-anchor-mismatch/,
    /policy-snapshot-deny/, /policy-snapshot/,
    /LINUX_ADMIN_POLICY_FILE_CUSTODY_PASS/,
  ]) assert.match(script, expression);
});

test('policy/witness forward publication mismatches deny; consistent whole rollback is explicitly unprotected', () => {
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-admin-policy-file-acceptance.sh'), 'utf8',
  );
  for (const marker of [
    /init-policy-bytes-v2/, /write-policy-anchor-v2/,
    /E_POLICY_FORWARD_POLICY_WITH_STALE_WITNESS/,
    /E_POLICY_FORWARD_WITNESS_WITH_STALE_POLICY/,
    /E_POLICY_ROLLBACK_DB_ONLY/,
    /E_POLICY_FULL_STATE_ROLLBACK_IS_UNDETECTABLE/,
    /policy-snapshot-v2/, /policy-snapshot-deny/,
  ]) assert.match(script, marker);
});

test('protected SQLite main-image snapshot rejects real rollback and WAL sidecars', () => {
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-admin-policy-file-acceptance.sh'), 'utf8',
  );
  for (const marker of [
    /E_POLICY_JOURNAL_SIDECAR_DENIED/,
    /E_POLICY_WAL_SIDECAR_DENIED/,
    /E_POLICY_SHM_SIDECAR_DENIED/,
    /E_POLICY_SYMLINK_SIDECAR_DENIED/,
    /policy-snapshot-deny/,
  ]) assert.match(script, marker);
});

test('Linux OS-pinned policy inode must still occupy fixed name after the read', () => {
  const implementation = fs.readFileSync(
    path.join(repo, 'native/authority-service/src/linux_epoch_anchor.rs'), 'utf8',
  );
  assert.match(implementation, /fn require_pinned_policy_name\(/);
  assert.match(implementation, /libc::fstatat\(/);
  assert.match(implementation, /libc::AT_SYMLINK_NOFOLLOW/);
  assert.match(implementation, /pinned_policy_file_denies_final_name_replacement_after_fd_acquisition/);
  assert.match(implementation, /require_pinned_policy_name\(&self\.directory, &self\.file\)/);
});

test('Linux observed-policy generation monitor must revoke permanently on any drift', () => {
  const source = fs.readFileSync(
    path.join(repo, 'native/authority-service/src/linux_policy_epoch_monitor.rs'), 'utf8',
  );
  for (const m of [
    /struct PolicyEpochMonitor/,
    /fn from_current_os_attested\(/,
    /fn revalidate_current\(/,
    /fn observe_or_poison\(/,
    /fn sticky_denial_prevents_reactivation_after_rollback\(/,
    /fn changed_epoch_or_digest_revokes_the_observed_generation\(/,
  ]) assert.match(source, m);
});

test('Linux policy monitor is exercised in one real service process across admin update and restoration', () => {
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-admin-policy-file-acceptance.sh'), 'utf8',
  );
  const probe = fs.readFileSync(
    path.join(repo, 'native/authority-service/examples/linux_epoch_anchor_probe.rs'), 'utf8',
  );
  for (const marker of [
    /coproc POLICY_MON/,
    /policy-monitor-stdin/,
    /E_POLICY_MONITOR_STICKY_DENIAL/,
    /read -r -t 10/,
    /MONITOR_READY/,
    /MONITOR_MATCH/,
    /MONITOR_DENIED/,
  ]) assert.match(script, marker);
  assert.match(probe, /PolicyEpochMonitor::from_current_os_attested/);
  assert.match(probe, /monitor.revalidate_current\(\)/);
});

test('root-admin epoch witness is exercised under actual NNP service and foreign principals', () => {
  for (const [name, command] of [
    ['Lint Linux protected epoch witness acceptance',
      'shellcheck --severity=warning test/security/t011-linux-epoch-anchor-acceptance.sh && bash -n test/security/t011-linux-epoch-anchor-acceptance.sh'],
    ['Prove root-admin epoch witness under actual Linux service credentials',
      'bash test/security/t011-linux-epoch-anchor-acceptance.sh'],
  ]) {
    assert.ok(workflow.includes(`      - name: ${name}\n        if: matrix.target == 'linux-x64'\n        run: ${command}`));
  }
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-epoch-anchor-acceptance.sh'), 'utf8',
  );
  assert.match(script, /RUNNER_ENVIRONMENT/);
  assert.match(script, /E_ANCHOR_NO_NEW_PRIVS_NOT_PROVEN/);
  assert.match(script, /NoNewPrivs:/);
  assert.match(script, /expect_verdict MATCH sudo -n -u jdc-authority -- setpriv --no-new-privs -- "\$probe" match/);
  assert.match(script, /expect_verdict DENIED sudo -n -u jdc-mcp-client -- setpriv --no-new-privs -- "\$probe" deny/);
  assert.match(script, /expect_verdict DENIED sudo -n -- setpriv --no-new-privs -- "\$probe" deny/);
  assert.match(script, /sudo -n chmod 0660 -- "\$anchor"/);
  assert.match(script, /sudo -n chown jdc-authority:jdc-authority -- "\$anchor"/);
  assert.match(script, /sudo -n truncate -s 39 -- "\$anchor"/);
  assert.match(script, /sudo -n ln -s -- "\$source_file" "\$anchor"/);
  assert.match(script, /sudo -n ln -- "\$anchor" "\$hardlink_alias"/);
  assert.match(script, /E_ANCHOR_HARDLINK_OBJECT_NOT_PROVEN/);
  assert.match(script, /sudo -n stat -c '%h' -- "\$anchor"/);
  assert.match(script, /expect_verdict DENIED sudo -n -u jdc-authority -- setpriv --no-new-privs -- "\$probe" deny/);
  assert.match(script, /sudo -n rm -- "\$hardlink_alias"/);
  assert.match(script, /E_ANCHOR_CANONICAL_BYTES_CHANGED/);
  assert.doesNotMatch(script, /expect_verdict MATCH sudo -n -u jdc-authority -- "\$probe"/);
});
