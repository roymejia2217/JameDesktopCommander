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

test('ephemeral runner requires precise audit outcomes, not arbitrary nonzero failure', () => {
  assert.match(acceptance, /ServiceSpecificExitCode/);
  assert.match(acceptance, /ServiceSpecificExitCode -notin @\(1, 3\)/);
  assert.match(acceptance, /E_SCM_TOKEN_OBSERVATION_INVALID/);
  assert.match(acceptance, /E_SCM_WRONG_DENIAL_REASON/);
  assert.match(acceptance, /E_SCM_PRIVILEGE_BASELINE_UNREVIEWED/);
  assert.match(acceptance, /E_SCM_PROCESS_STILL_RUNNING/);
});
