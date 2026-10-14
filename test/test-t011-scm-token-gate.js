import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const service = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_scm.rs'), 'utf8');
const acceptance = fs.readFileSync(path.join(root, 'test/security/t011-windows-scm-acceptance.ps1'), 'utf8');

test('real SCM deny-only exit must depend on kernel token audit', () => {
  assert.match(service, /windows_token::observe_current_process_token\(\)/);
  assert.doesNotMatch(service, /jdc_authority_service::verify_service_identity\(\)/);
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  assert.doesNotMatch(observer, /crate::verify_service_identity\(\)/);
  assert.match(observer, /query\(token, TokenUser\)/);
  assert.match(observer, /\.sid\(user\.User\.Sid\)/);
  assert.match(observer, /TokenFinding::IdentityMismatch/);
  assert.equal((observer.match(/OpenProcessToken\(/g) ?? []).length, 1,
    'SCM observation must own one process token handle');
  assert.match(service, /scm_terminal_denial_code/);
  assert.match(service, /ServiceState::Stopped/);
  assert.doesNotMatch(service, /ServiceState::Running/);
  assert.doesNotMatch(service, /ServiceControlAccept::STOP/);
});

test('SCM mandatory integrity label uses the exact bounded S-1-16 single-RID parser', () => {
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  const policy = fs.readFileSync(path.join(root, 'native/authority-service/src/token_policy.rs'), 'utf8');
  assert.match(observer, /info\.sid\(label\.Label\.Sid\)/);
  assert.match(observer, /integrity_sid_rid\(sid\)\.ok_or\(TokenUnverifiable\)/);
  assert.match(policy, /pub fn integrity_sid_rid\(sid: &\[u8\]\)/);
  assert.doesNotMatch(observer, /sid\[sid\.len\(\) - 4\.\.\]/);
});

test('SCM privilege LUIDs and flags are checked before every name lookup', () => {
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  const policy = fs.readFileSync(path.join(root, 'native/authority-service/src/token_policy.rs'), 'utf8');
  assert.match(observer, /resolve_enabled_privilege_names\(&records,/);
  assert.match(observer, /LookupPrivilegeNameW\(/);
  assert.match(observer, /validated_enabled_privilege_indices\(records\)/);
  assert.match(policy, /pub fn validated_enabled_privilege_indices\(/);
  assert.match(policy, /luids\.insert\(\(record\.luid_low, record\.luid_high\)\)/);
  assert.match(policy, /record\.attributes & !ALLOWED_FLAGS/);
  assert.match(observer, /seen_names\.insert\(name\.to_ascii_lowercase\(\)\)/);
});

test('SCM evidence snapshot is private, in-process and cannot export token material', () => {
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  const scm = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_scm.rs'), 'utf8');
  assert.match(observer, /struct VerifiedScmTokenSnapshot \{/);
  assert.doesNotMatch(observer, /pub\s+(?:struct|fn)\s+(?:VerifiedScmTokenSnapshot|verified_snapshot)/);
  assert.match(observer, /let Some\(user_sid\) = token_user_matches_service\(token\.0, &expected\)\?/);
  assert.match(observer, /let snapshot = verified_snapshot\(token\.0, &expected, user_sid\)\?/);
  assert.match(observer, /Ok\(snapshot\.classify\(\)\)/);
  assert.doesNotMatch(observer, /serde|serde_json|println!|eprintln!|File::create|OpenOptions::new|TcpStream|NamedPipe/);
  assert.match(scm, /scm_terminal_denial_code\(observation\)/);
  // Comments may describe TokenPrivileges; executable SCM code must not
  // read, serialize or export names directly.
  const scmCode = scm.replace(/^\s*\/\/.*$/gm, '');
  assert.doesNotMatch(scmCode, /enabled_privileges|TokenPrivileges|write_all\(/);
  assert.doesNotMatch(acceptance, /Write-Output.*(?:SeDebugPrivilege|SeChangeNotifyPrivilege|TokenGroups)/i);
});

test('SCM group inventory copies bounded SID bytes without exporting raw token pointers', () => {
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  const scm = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_scm.rs'), 'utf8');
  assert.match(observer, /struct OwnedSidGroup \{[\s\S]*?sid: Vec<u8>,[\s\S]*?attributes: u32,/);
  assert.match(observer, /self\.sid\(group\.Sid\)\?\.to_vec\(\)/);
  assert.match(observer, /copied_normal_groups\.push\(groups\.copied_sid_group\(group\)\?\)/);
  assert.match(observer, /copied_restricted_groups\.push\(restricted\.copied_sid_group\(group\)\?\)/);
  assert.match(observer, /normal_groups: copied_normal_groups/);
  assert.match(observer, /restricted_groups: copied_restricted_groups/);
  assert.match(observer, /\.chain\(self\.restricted_groups\.iter\(\)\)/);
  assert.doesNotMatch(observer, /pub\s+struct OwnedSidGroup|pub\s+fn verified_snapshot/);
  assert.doesNotMatch(scm, /(?:println!|write_all|OpenOptions|File::create).*sid/i);
});

test('SCM owns the verified token-user SID, compares it to expected service SID, and never publishes it', () => {
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  assert.match(observer, /fn token_user_matches_service\(/);
  assert.match(observer, /EqualSid\(user\.User\.Sid, expected_sid\)/);
  assert.match(observer, /Ok\(Some\(validated_sid\.to_vec\(\)\)\)/);
  assert.match(observer, /token_user_sid: matched_user_sid/);
  assert.match(observer, /service_account_sid,/);
  assert.match(observer, /self\.token_user_sid != self\.service_account_sid/);
  assert.match(observer, /bounded_sid_bytes\(&self\.token_user_sid\)/);
  assert.doesNotMatch(observer, /pub\s+struct VerifiedScmTokenSnapshot/);
  assert.doesNotMatch(service, /token_user_sid|service_account_sid|write_all\(/);
});

test('ephemeral runner requires precise audit outcomes, not arbitrary nonzero failure', () => {
  assert.match(acceptance, /ServiceSpecificExitCode/);
  assert.match(acceptance, /ServiceSpecificExitCode -notin @\(1, 3\)/);
  assert.match(acceptance, /E_SCM_TOKEN_OBSERVATION_INVALID/);
  assert.match(acceptance, /E_SCM_WRONG_DENIAL_REASON/);
  assert.match(acceptance, /E_SCM_PRIVILEGE_BASELINE_UNREVIEWED/);
  assert.match(acceptance, /E_SCM_PROCESS_STILL_RUNNING/);
});
