import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(repo,
  'native/authority-service/src/windows_epoch_anchor.rs'), 'utf8');
const fixture = fs.readFileSync(path.join(repo,
  'test/security/t011-windows-registry-epoch-acceptance.ps1'), 'utf8');

test('Windows witness independently authenticates all managed registry ancestors', () => {
  assert.match(source, /const ADMIN_PARENT_PATH: &str/);
  assert.match(source, /const AUTHORITY_PARENT_PATH: &str/);
  assert.match(source, /open_verified_key\(ADMIN_PARENT_PATH, &service_sid\)/);
  assert.match(source, /open_verified_key\(AUTHORITY_PARENT_PATH, &service_sid\)/);
  assert.match(source, /open_verified_key\(KEY_PATH, &service_sid\)/);
});

test('SCM failures preserve primary evidence and report cleanup failures separately', () => {
  assert.match(fixture, /T011_EPOCH_CASE_\$\{scenario\}_PASS/);
  assert.match(fixture, /\$hadPrimaryFailure = \$true/);
  assert.match(fixture, /E_EPOCH_PRIMARY_FAILURE/);
  assert.match(fixture, /E_EPOCH_CLEANUP_REGISTRY_FAILED/);
  assert.match(fixture, /if \(-not \$hadPrimaryFailure\)/);
});

test('admin retains explicit child rights before parent ACL hardening', () => {
  const child = fixture.indexOf('Set-ExactAdminControlledKey $registryAuthority $false');
  const parent = fixture.indexOf('Set-ExactAdminControlledKey $registryParent $false');
  assert.ok(child >= 0 && parent >= 0 && child < parent,
    'secure the Authority child before the parent DACL is made noninheriting');
  assert.match(fixture, /SetAccessRuleProtection\(\$false, \$false\)/);
  assert.match(fixture, /T011_EPOCH_AUTHORITY_EXPLICIT_ADMIN_RIGHTS/);
});

test('hosted SCM fixture denies leaf-only and partially guarded authority', () => {
  assert.match(fixture, /UNTRUSTED_REGISTRY_ROOT_ANCESTOR/);
  assert.match(fixture, /UNTRUSTED_REGISTRY_AUTHORITY_ANCESTOR/);
  assert.match(fixture, /FOREIGN_REGISTRY_ROOT_ANCESTOR/);
  assert.match(fixture, /FOREIGN_REGISTRY_AUTHORITY_ANCESTOR/);
  assert.match(fixture, /Set-ExactAdminControlledKey \$registryParent \$false/);
  assert.match(fixture, /Set-ExactAdminControlledKey \$registryAuthority \$false/);
});
