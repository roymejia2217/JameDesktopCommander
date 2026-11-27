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
  assert.match(issuer, /SYS_pidfd_getfd/);
  assert.match(issuer, /Some\(libc::EACCES\) \| Some\(libc::EPERM\)/);
  assert.match(issuer, /inspect-control/);
  assert.match(issuer, /inspect-protected/);
  assert.match(issuer, /T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE/);
  assert.equal((script.match(/grep -Fxq T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE/g) || []).length, 2);
  assert.match(script, /grep -Fxq 'T011_LINUX_SDK_POST_EXEC_CUSTODY_PASS_NONRELEASE'[\s\\]+<<<"\$sdk_issuer_output"/);
});
