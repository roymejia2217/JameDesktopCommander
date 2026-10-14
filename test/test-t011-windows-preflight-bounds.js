import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const lib = fs.readFileSync(path.join(root, 'native/authority-service/src/lib.rs'), 'utf8');
const windows = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_token.rs'), 'utf8');
const observer = fs.readFileSync(path.join(root, 'native/authority-service/src/windows_scm.rs'), 'utf8');

test('standalone Windows C4g preflight delegates to bounded shared token primitives', () => {
  assert.match(lib, /windows_token::verify_current_process_identity\(\)/);
  assert.doesNotMatch(lib, /GetTokenInformation|LookupAccountNameW|EqualSid|OpenProcessToken/);
  assert.match(windows, /pub\(crate\) fn verify_current_process_identity\(\)/);
  assert.match(windows, /fn token_user_matches_service\(/);
  assert.match(windows, /identity_info\.sid\(user\.User\.Sid\)/);
  assert.match(windows, /query\(token, TokenUser\)/);
  assert.equal((windows.match(/OpenProcessToken\(/g) ?? []).length, 1);
});

test('SCM still checks every token attribute from its own opened token', () => {
  assert.match(observer, /windows_token::observe_current_process_token\(\)/);
  assert.doesNotMatch(observer, /jdc_authority_service::verify_service_identity\(/);
  assert.match(windows, /token_user_matches_service\(token\.0, &expected\)/);
  assert.match(windows, /verified_snapshot\(token\.0, &expected\)/);
  assert.match(windows, /fn verified_snapshot\(/);
  assert.match(windows, /query\(token, TokenGroups\)/);
  assert.match(windows, /query\(token, TokenPrivileges\)/);
});
