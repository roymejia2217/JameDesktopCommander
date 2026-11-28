import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';

const repo=path.resolve(import.meta.dirname,'..');
const workflow=fs.readFileSync(path.join(repo,'.github/workflows/t011-capability-feasibility.yml'),'utf8').replace(/\r\n/g,'\n');
test('Windows SCM acceptance runs within the native security matrix',()=>{
  assert.match(workflow,/^  native-probe:\n/m);
  assert.doesNotMatch(workflow,/^  windows-scm-acceptance:/m);
  const step = YAML.parse(workflow).jobs['native-probe'].steps
    .find(item => item.id === 'windows_scm_acceptance');
  assert.ok(step, 'Native Windows SCM acceptance step is required');
  assert.equal(step.if, "matrix.target == 'win32-x64'");
  assert.equal(step.run, 'pwsh -NoProfile -File test/security/t011-windows-scm-acceptance.ps1');
  const steps = YAML.parse(workflow).jobs['native-probe'].steps;
  const sdk = steps.find(item => item.id === 'windows_scm_sdk_read');
  assert.ok(sdk, 'Real SDK integration requires a separate mandatory step');
  assert.equal(sdk.if, step.if);
  assert.equal(sdk.shell, 'pwsh');
  assert.ok(steps.indexOf(sdk) < steps.findIndex(item => item.id === step.id));
  assert.ok(!sdk['continue-on-error']);
  assert.match(sdk.run, /observation::job_fixture::sdk_read::tests::real_jdc_sdk_fixed_read_and_wrong_connector_denial -- --ignored --exact --nocapture/);
  assert.match(sdk.run, /E_SCM_LOCAL_SDK_VERDICT_MISSING/);
  assert.ok(workflow.includes('cargo +1.91.1 build --locked --bin jdc-authority-scm'));
});
test('SCM acceptance guards ephemeral host and verifies service-specific denial and cleanup',()=>{
  const script=fs.readFileSync(path.join(repo,'test/security/t011-windows-scm-acceptance.ps1'),'utf8');
  for(const marker of [
    'GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS','sc.exe','NT SERVICE',
    'JameDesktopCommanderAuthority','sidtype','ServiceControllerStatus]::Stopped',
    'ServiceSpecificExitCode','Get-CimInstance','try {','finally {','Get-FileHash',
    'E_SCM_WRONG_DENIAL_REASON','Remove-Item',
  ]) assert.ok(script.includes(marker),`Missing real SCM acceptance guard ${marker}`);
  assert.ok(!script.includes('start= auto'),'experimental SCM service must never autostart');
  assert.ok(!script.includes('Restart-Service'),'test must not hide process exit');
});
