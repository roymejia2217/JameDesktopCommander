import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';

const root = path.resolve(import.meta.dirname, '..');
const file = path.join(root,'packaging/experimental/windows/jdc-authority-service.sddl');
const acceptance = fs.readFileSync(path.join(root,'test/security/t011-windows-scm-acceptance.ps1'),'utf8');
const workflow = fs.readFileSync(path.join(root,'.github/workflows/t011-capability-feasibility.yml'),'utf8').replace(/\r\n/g,'\n');

test('experimental SCM DACL grants mutation only to SYSTEM and Administrators',()=>{
  const sddl = fs.readFileSync(file,'utf8').trim();
  assert.equal(sddl,'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;AU)');
  assert.equal(sddl.split('(A;;').length - 1,3);
});
test('SCM tests prove real non-admin child process and service-object rights rather than console success',()=>{
  for(const token of [
    'New-LocalUser','Get-LocalGroupMember','Start-Process','-Credential',
    'sc.exe','sdset','sdshow','RawSecurityDescriptor',
    'DiscretionaryAclProtected','E_SCM_ACL_UNEXPECTED_GRANT',
    'E_SCM_ATTACKER_QUERY_FAILED','E_SCM_ATTACKER_MUTATION_SUCCEEDED',
    'E_SCM_SERVICE_DACL_CHANGED','finally {','Remove-LocalUser',
  ]) assert.ok(acceptance.includes(token),token);
  assert.match(acceptance,/\$sc config/);
  assert.match(acceptance,/\$sc delete/);
  assert.match(acceptance,/\$sc start/);
  assert.match(acceptance,/\$sc sdset/);
  assert.match(acceptance,/\$sc sdshow/);
  assert.doesNotMatch(acceptance,/start= auto/);
});
test('existing governed Windows native acceptance remains mandatory',()=>{
  const step = YAML.parse(workflow).jobs['native-probe'].steps
    .find(item => item.id === 'windows_scm_acceptance');
  assert.ok(step, 'SCM acceptance step must remain in the native security job');
  assert.equal(step.if, "matrix.target == 'win32-x64'");
  assert.equal(step.run, 'pwsh -NoProfile -File test/security/t011-windows-scm-acceptance.ps1');
  assert.doesNotMatch(workflow,/^  scm-dacl-only-acceptance:/m);
});
