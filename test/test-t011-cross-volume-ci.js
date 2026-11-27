import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(path.join(repo,
  '.github/workflows/t011-capability-feasibility.yml'), 'utf8');
const linux = 'test/security/t011-linux-storage-domain-acceptance.sh';
const windows = 'test/security/t011-windows-storage-domain-acceptance.ps1';

test('cross-volume custody exercises real OS fixtures on both hosted platforms', () => {
  for (const [script, invocation] of [
    [linux, 'bash test/security/t011-linux-storage-domain-acceptance.sh'],
    [windows, 'pwsh -NoProfile -File test/security/t011-windows-storage-domain-acceptance.ps1'],
  ]) {
    assert.ok(fs.existsSync(path.join(repo, script)), `missing ${script}`);
    assert.ok(workflow.includes(invocation), `native CI must execute ${invocation}`);
  }
});
test('cross-volume proof includes positive links, genuine denials and outside integrity', () => {
  for (const source of [linux, windows]) {
    const content = fs.readFileSync(path.join(repo, source), 'utf8');
    assert.match(content, /RUNNER_ENVIRONMENT/);
    assert.match(content, /SAME_VOLUME_HARDLINK_PASS/);
    assert.match(content, /CROSS_VOLUME_HARDLINK_DENIED/);
    assert.match(content, /EXTERIOR_BYTES_UNCHANGED/);
    assert.doesNotMatch(content, /continue-on-error/);
  }
});

test('hosted SDK state is private to the issued mount namespace for all three real SDK paths', () => {
  const harness = fs.readFileSync(path.join(repo, linux), 'utf8');
  const issuer = fs.readFileSync(path.join(repo,
    'native/authority-service/examples/linux_peered_read_proof.rs'), 'utf8');
  assert.match(harness, /install -d -o root -g root -m 0700 -- "\$base\/client-state"/);
  const launch = issuer.slice(issuer.indexOf('fn launch_sdk('), issuer.indexOf('fn verify_sdk_process_custody('));
  assert.ok(launch.indexOf('mount_sdk_state(') >= 0);
  assert.ok(launch.indexOf('mount_sdk_state(') < launch.indexOf('libc::unshare(libc::CLONE_NEWUSER)'));
  assert.match(issuer, /libc::CLONE_NEWNS/);
  assert.match(issuer, /libc::MS_PRIVATE/);
  assert.match(issuer, /libc::MS_NOEXEC/);
  assert.match(issuer, /NS_GET_USERNS/);
  assert.match(issuer, /verify_sdk_state/);
  assert.match(issuer, /\/root\/|\/root\{/);
  assert.match(issuer, /T011_LINUX_SDK_PRIVATE_STATE_PASS_NONRELEASE/);
  assert.equal((harness.match(/grep -Fxq .*T011_LINUX_SDK_PRIVATE_STATE_PASS_NONRELEASE/g) || []).length, 3);
  for (const fixture of ['t011-issued-sdk-native-read.mjs', 't011-issued-sdk-native-mutations.mjs']) {
    const source = fs.readFileSync(path.join(repo, 'test/security/support', fixture), 'utf8');
    const canary = source.indexOf('sdk-state-proof');
    const ready = source.indexOf("writeSync(0, 'R')");
    assert.ok(canary >= 0 && ready > canary, 'real SDK must prove private write before release');
  }
});

test('hosted Linux SDK issuance requires enforced process custody before native attestation', () => {
  const script = fs.readFileSync(path.join(repo, linux), 'utf8');
  const issuer = fs.readFileSync(path.join(repo,
    'native/authority-service/examples/linux_peered_read_proof.rs'), 'utf8');
  assert.match(script, /apparmor_parser -a -K/);
  assert.match(script, /apparmor_parser -R -K/);
  assert.match(script, /deny ptrace \(readby, tracedby\),/); // codespell:ignore readby
  assert.match(script, /node_binary="\$base\/sdk-node"/);
  assert.match(script, /\/sys\/kernel\/security\/apparmor\/profiles/);
  const custody = issuer.indexOf('verify_sdk_process_custody(',
    issuer.indexOf('fn issue('));
  const attestation = issuer.indexOf('send_attestation(&channel', custody);
  assert.ok(custody >= 0 && attestation > custody);
  assert.match(issuer, /\/attr\/apparmor\/current/);
  // The target profile alone cannot exclude an unconfined same-UID peer.
  // A root-created user namespace must precede the credential drop and exec.
  assert.match(issuer, /libc::unshare\(libc::CLONE_NEWUSER\)/);
  assert.match(issuer, /NS_GET_OWNER_UID/);
  assert.match(issuer, /NS_GET_PARENT/);
  assert.match(issuer, /uid_map/);
  assert.match(issuer, /gid_map/);
  assert.match(issuer, /PR_SET_NO_NEW_PRIVS/);
  assert.match(issuer, /verify_sdk_namespace/);
  assert.match(issuer, /launch-sdk/);
  for (const fixture of ['t011-issued-sdk-native-read.mjs', 't011-issued-sdk-native-mutations.mjs']) {
    const source = fs.readFileSync(path.join(repo, 'test/security/support', fixture), 'utf8');
    assert.match(source, /writeSync\(0, /);
    assert.match(source, /readSync\(0, /);
  }
  assert.match(issuer, /SYS_pidfd_getfd/);
  assert.match(issuer, /Some\(libc::EACCES\) \| Some\(libc::EPERM\)/);
  assert.match(issuer, /inspect-control/);
  assert.match(issuer, /inspect-protected/);
  assert.match(issuer, /T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE/);
  assert.equal((script.match(/grep -Fxq T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE/g) || []).length, 2);
  assert.match(script, /grep -Fxq 'T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE'[\s\\]+<<<"\$sdk_issuer_output"/);
});
