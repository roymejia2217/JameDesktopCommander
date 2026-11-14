import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
const root = path.resolve(import.meta.dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('native T011 compiles Windows named pipe proof only in nonrelease CI', () => {
  const ci = read('.github/workflows/t011-capability-feasibility.yml');
  assert.match(ci, /build --locked --examples --manifest-path native\/authority-service\/Cargo\.toml/);
  assert.match(ci, /t011-windows-storage-domain-acceptance\.ps1/);
  assert.match(ci, /if: matrix\.target == 'win32-x64'/);
});
test('Windows pipe CI uses three actual OS accounts and a real SID denial', () => {
  const script = read('test/security/t011-windows-storage-domain-acceptance.ps1');
  assert.match(script, /New-CIIdentity \$clientName/);
  assert.match(script, /-Credential \$service\.Credential/);
  assert.match(script, /Invoke-PeerClient \$attacker\.Credential/);
  assert.match(script, /Invoke-PeerClient \$client\.Credential/);
  assert.match(script, /T011_WINDOWS_SEPARATE_SID_PIPE_ACCEPTED_NONRELEASE/);
  assert.match(script, /E_PIPE_CLIENT_(?:FAILED|TIMEOUT)/);
  assert.match(script, /E_STORAGE_EXTERIOR_BYTES_CHANGED/);
  assert.match(script, /RUNNER_ENVIRONMENT/);
});

test('Windows native pipe has explicit DACL, local-only exclusive instance and drained replies', () => {
  const example = read('native/authority-service/examples/windows_named_pipe_peer_proof.rs');
  assert.match(example, /ConvertStringSecurityDescriptorToSecurityDescriptorW/);
  assert.match(example, /FILE_FLAG_FIRST_PIPE_INSTANCE/);
  assert.match(example, /PIPE_REJECT_REMOTE_CLIENTS/);
  assert.match(example, /FlushFileBuffers\(pipe\.0\)/);
  assert.doesNotMatch(example, /FILE_GENERIC_WRITE/);
});

test('Windows hosted peer test awaits a service-owned readiness event without polling', () => {
  const script = read('test/security/t011-windows-storage-domain-acceptance.ps1');
  const example = read('native/authority-service/examples/windows_named_pipe_peer_proof.rs');
  assert.match(script, /Set-CustodyAcl \$readyDir/);
  assert.match(script, /Register-ObjectEvent -InputObject \$peerReadyWatcher -EventName Created/);
  assert.match(script, /Wait-Event -SourceIdentifier \$peerReadySourceId -Timeout 12/);
  assert.match(script, /Unregister-Event -SourceIdentifier \$peerReadySourceId/);
  assert.doesNotMatch(script, /Start-Sleep/);
  assert.match(example, /\.create_new\(true\)/);
  assert.match(example, /E_PIPE_READY_SIGNAL/);
  assert.match(example, /ready_path/);
});

test('Windows failed client retains only a classified error code', () => {
  const script = read('test/security/t011-windows-storage-domain-acceptance.ps1');
  assert.ok(script.includes("'-cmatch '^E_PIPE_[A-Z0-9_]+$'") ||
    script.includes("-cmatch '^E_PIPE_[A-Z0-9_]+$'"));
  assert.match(script, /NO_SAFE_DIAGNOSTIC/);
  assert.match(script, /E_PIPE_CLIENT_FAILED_\$\(\$mode\)_\$reason/);
});
