import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const ci = fs.readFileSync(path.join(repo,'.github/workflows/t011-capability-feasibility.yml'),'utf8').replace(/\r\n/g,'\n');
test('systemd sysusers provisions CI service account before Linux identity and custody acceptance',()=>{
  assert.match(ci,/^  native-probe:\n/m);
  assert.doesNotMatch(ci,/^  linux-service-acceptance:/m);
  assert.match(ci,/sudo systemd-sysusers "\$sysusers_file"/);
  assert.ok(ci.indexOf('sudo systemd-sysusers "$sysusers_file"') < ci.indexOf('Prove Linux distinct-principal custody'));
  const custody = fs.readFileSync(path.join(repo,'test/security/t011-linux-custody-acceptance.sh'),'utf8');
  assert.doesNotMatch(custody,/\buseradd\b/);
  assert.match(custody,/getent passwd jdc-authority/);
  assert.match(custody,/E_CUSTODY_SERVICE_PRINCIPAL_NOT_PROVISIONED/);
});
test('service real-lifecycle check uses official systemctl and journalctl in existing Linux native gate',()=>{
  for (const v of ['systemctl daemon-reload','systemctl --wait start "$unit_name"','systemctl show','journalctl','E_POLICY_UNAVAILABLE']) {
    const script=fs.readFileSync(path.join(repo,'test/security/t011-systemd-lifecycle-acceptance.sh'),'utf8');
    assert.ok(script.includes(v),v);
  }
  assert.match(ci,/run: bash test\/security\/t011-systemd-lifecycle-acceptance\.sh/);
  assert.match(ci,/shellcheck --severity=warning test\/security\/t011-systemd-lifecycle-acceptance\.sh/);
  const script=fs.readFileSync(path.join(repo,'test/security/t011-systemd-lifecycle-acceptance.sh'),'utf8');
  assert.match(script,/RUNNER_ENVIRONMENT/);
  assert.match(script,/set -euo pipefail/);
  assert.match(script,/trap .*EXIT/);
  assert.match(script,/E_CUSTODY_UNAUTHORIZED/);
  assert.match(script,/timeout --kill-after=5s 30s/);
  assert.match(script,/E_SYSTEMD_TERMINATION_TIMEOUT/);
  assert.doesNotMatch(script,/if sudo -n systemctl start/);
});