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
    'jdc_authority_service::verify_service_identity',
    'ServiceControl::Interrogate',
    'ServiceControlAccept::empty()',
    'E_SCM_DISPATCHER_REQUIRED',
  ]) assert.ok(content.includes(marker), `Missing deny-only SCM contract: ${marker}`);
  assert.doesNotMatch(content, /ServiceState::Running|ServiceControlAccept::STOP|OpenProcess\(|CreateFile\(|TcpListener|UnixListener/);
  assert.doesNotMatch(content, /(?<![A-Za-z])ServiceExitCode::Win32\(0\)/);
});

test('SCM dispatcher is compiled and linted by existing required Windows native job', () => {
  assert.ok(workflow.includes('cargo +1.91.1 build --locked --bin jdc-authority-scm --manifest-path native/authority-service/Cargo.toml'));
  assert.ok(workflow.includes("if: matrix.target == 'win32-x64'"));
  assert.ok(workflow.includes('cargo +1.91.1 clippy --locked --bin jdc-authority-scm --manifest-path native/authority-service/Cargo.toml -- -D warnings'));
  assert.doesNotMatch(workflow, /^  scm-only-validation:/m);
});
