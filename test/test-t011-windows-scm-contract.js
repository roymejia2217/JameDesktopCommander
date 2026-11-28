import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const crate = fs.readFileSync(path.join(root, 'native/authority-service/Cargo.toml'), 'utf8');
const binaryPath = 'native/authority-service/src/windows_scm.rs';
const workflow = fs.readFileSync(path.join(root, '.github/workflows/t011-capability-feasibility.yml'), 'utf8');

test('Windows SCM dispatcher is a separate unreleased, fully locked Rust service target', () => {
  assert.match(crate, /name = "jdc-authority-scm"/);
  assert.match(crate, /windows-service = \{ version = "=0\.8\.1"\s*\}/);
  const content = fs.readFileSync(path.join(root, binaryPath), 'utf8');
  for (const marker of [
    'service_dispatcher::start',
    'define_windows_service!',
    'service_control_handler::register',
    'ServiceState::Stopped',
    'ServiceExitCode::ServiceSpecific',
    'jdc_authority_service::windows_token::observe_current_process_token',
    'ServiceControl::Interrogate',
    'ServiceControlAccept::empty()',
    'E_SCM_DISPATCHER_REQUIRED',
  ]) assert.ok(content.includes(marker), `Missing deny-only SCM contract: ${marker}`);
  // Identity and privilege claims MUST derive from the same kernel token.
  const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
  assert.doesNotMatch(content, /jdc_authority_service::verify_service_identity\(/);
  assert.doesNotMatch(observer, /crate::verify_service_identity\(/);
  assert.equal((observer.match(/OpenProcessToken\(/g) ?? []).length, 1);
  assert.match(observer, /query\(token, TokenUser\)/);
  assert.match(observer, /identity_info\.sid\(user\.User\.Sid\)/);
  assert.match(observer, /TokenFinding::IdentityMismatch/);
  assert.doesNotMatch(content, /ServiceState::Running|ServiceControlAccept::STOP|OpenProcess\(|CreateFile\(|TcpListener|UnixListener/);
  assert.doesNotMatch(content, /(?<![A-Za-z])ServiceExitCode::Win32\(0\)/);
});

test('SCM dispatcher is compiled and linted by existing required Windows native job', () => {
  assert.ok(workflow.includes('cargo +1.91.1 build --locked --bin jdc-authority-scm --manifest-path native/authority-service/Cargo.toml'));
  assert.ok(workflow.includes("if: matrix.target == 'win32-x64'"));
  assert.ok(workflow.includes('cargo +1.91.1 clippy --locked --bin jdc-authority-scm --manifest-path native/authority-service/Cargo.toml -- -D warnings'));
  assert.doesNotMatch(workflow, /^  scm-only-validation:/m);
});

test('SCM distinct-principal observation is a mandatory nonrelease experiment', () => {
  const proof = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_scm_issued_proof.rs'), 'utf8');
  const acceptance = fs.readFileSync(path.join(root, 'test/security/t011-windows-scm-acceptance.ps1'), 'utf8');
  assert.match(proof, /--issuer-observer-proof/);
  assert.match(proof, /--authority-observer-proof/);
  assert.match(acceptance, /JameDesktopCommanderIssuer/);
  assert.match(acceptance, /T011_WINDOWS_SCM_DISTINCT_PRINCIPAL_PIN_PASS_NONRELEASE/);
  assert.match(acceptance, /T011_WINDOWS_SCM_JOB_HANDOFF_PASS_NONRELEASE/);
  assert.match(acceptance, /T011_WINDOWS_SCM_AUTHENTICATED_HANDOFF_PASS_NONRELEASE/);
  assert.match(acceptance, /T011_WINDOWS_SCM_PRIMARY_THREAD_PIN_PASS_NONRELEASE/);
  assert.match(acceptance, /E_SCM_JOB_HANDOFF_RECORD_CUSTODY/);
  assert.match(acceptance, /ServiceSpecificExitCode -ne \$expectedObserver/);
  assert.match(acceptance, /ServiceSpecificExitCode -ne \$expectedIssuer/);
  assert.match(acceptance, /\$expectedObserver = switch \(\$scenario\) \{ 'observer' \{ 8 \} 'resume' \{ 12 \} 'sdk-read' \{ 16 \} \}/);
  assert.match(acceptance, /\$expectedIssuer = switch \(\$scenario\) \{ 'observer' \{ 10 \} 'resume' \{ 14 \} 'sdk-read' \{ 18 \} \}/);
  assert.match(acceptance, /T011_WINDOWS_SCM_REAL_JDC_MANAGED_READ_PASS_NONRELEASE/);
  assert.match(proof, /--issuer-sdk-read-proof/);
  assert.match(proof, /--authority-sdk-read-proof/);
  assert.match(crate, /scm-storage-proof = \[/);
  assert.doesNotMatch(crate, /^default\s*=.*scm-storage-proof/m);
  for (const scenario of ['sdk-mutation', 'sdk-cancel']) {
    assert.ok(proof.includes('--issuer-' + scenario + '-proof'));
    assert.ok(proof.includes('--authority-' + scenario + '-proof'));
  }
  assert.match(acceptance, /'sdk-mutation' \{ 60 \} 'sdk-cancel' \{ 62 \}/);
  assert.match(acceptance, /'sdk-mutation' \{ 61 \} 'sdk-cancel' \{ 63 \}/);
  assert.match(acceptance, /T011_WINDOWS_SCM_ADMITTED_SDK_MUTATIONS_PASS_NONRELEASE/);
  assert.match(acceptance, /T011_WINDOWS_SCM_ADMITTED_SDK_CANCEL_REPLAY_PASS_NONRELEASE/);
  const storage = fs.readFileSync(path.join(root, 'test/security/t011-windows-storage-domain-acceptance.ps1'), 'utf8');
  assert.match(storage, /-StorageDrive \$volume -StorageGuid \$volumeGuid -StorageImage \$vhd/);
  assert.match(storage, /E_STORAGE_SCM_CLEANUP_UNVERIFIED/);
  assert.match(storage, /T011_WINDOWS_SCM_ADMITTED_OUTSIDE_INTEGRITY_PASS_NONRELEASE/);
  assert.match(storage, /Require-UserSuccess .*_READ_AUX/);
  assert.match(workflow, /id: windows_scm_admitted_storage/);
  assert.match(workflow, /--features scm-storage-proof/);
  assert.match(workflow, /t011-windows-storage-domain-acceptance\.ps1 -ScmStorageOnly/);
  assert.match(workflow, /T011_WINDOWS_SCM_ADMITTED_OUTSIDE_INTEGRITY_PASS_NONRELEASE/);
  assert.match(acceptance, /Assert-DualRoleAcl \$entry.FullName \$virtualSid \$issuerSid \$rx \$false/);
  assert.match(acceptance, /Set-RestrictedAcl \$sentinel \$false \$virtualSid/);
  assert.match(workflow, /observation::job_fixture::sdk_read::tests::real_jdc_sdk_fixed_read_and_wrong_connector_denial -- --ignored --exact --nocapture/);
  assert.match(workflow, /E_SCM_LOCAL_SDK_VERDICT_MISSING/);
  assert.match(acceptance, /T011_WINDOWS_SCM_CONTROLLED_RESUME_PASS_NONRELEASE/);
  assert.match(proof, /--issuer-resume-proof/);
  assert.match(proof, /--authority-resume-proof/);
  assert.match(acceptance, /privs.*SeChangeNotifyPrivilege/);
  assert.match(acceptance, /E_SCM_ISSUER_CLEANUP_FAILED/);
  assert.match(acceptance, /E_SCM_OBSERVER_PHASE_/);
  assert.match(acceptance, /E_SCM_ISSUER_PHASE_/);
  assert.match(acceptance, /ServiceSpecificExitCode -in \(20\.\.39\)/);
  assert.match(acceptance, /ServiceSpecificExitCode -in \(40\.\.48\)/);
  const denyOnly = fs.readFileSync(path.join(root, binaryPath), 'utf8');
  assert.doesNotMatch(denyOnly, /ServiceState::Running|ServiceControlAccept::STOP/);
});
