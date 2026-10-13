import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo=path.resolve(import.meta.dirname,'..');
const workflow=fs.readFileSync(path.join(repo,'.github/workflows/t011-capability-feasibility.yml'),'utf8').replace(/\r\n/g,'\n');
test('SCM real-host acceptance is mandatory within existing native Windows job',()=>{
  assert.match(workflow,/^  native-probe:\n/m);
  assert.doesNotMatch(workflow,/^  windows-scm-acceptance:/m);
  assert.ok(workflow.includes("      - name: Prove Windows SCM virtual account denies startup under its real token\n        if: matrix.target == 'win32-x64'\n        run: pwsh -NoProfile -File test/security/t011-windows-scm-acceptance.ps1"));
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
