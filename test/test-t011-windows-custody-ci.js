import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';

const root = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/t011-capability-feasibility.yml'), 'utf8').replace(/\r\n/g, '\n');
test('Windows custody acceptance runs within the native security matrix', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.match(workflow, /- runner: windows-2025\n            target: win32-x64/);
  assert.doesNotMatch(workflow, /^  windows-custody-acceptance:/m);
  const steps = YAML.parse(workflow).jobs['native-probe'].steps;
  const expected = [
    ['windows_custody_fixture',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml'],
    ['windows_custody_acceptance',
      'pwsh -NoProfile -File test/security/t011-windows-custody-acceptance.ps1'],
  ];
  const positions = expected.map(([id, command]) => {
    const index = steps.findIndex(step => step.id === id);
    assert.ok(index >= 0, `Missing mandatory Windows custody gate ${id}`);
    assert.equal(steps[index].if, "matrix.target == 'win32-x64'");
    assert.equal(steps[index].run, command);
    return index;
  });
  assert.ok(positions[0] < positions[1], 'Custody fixture must be built before acceptance');
  const script = fs.readFileSync(path.join(root, 'test/security/t011-windows-custody-acceptance.ps1'), 'utf8');
  for (const required of [
    /GITHUB_ACTIONS/, /RUNNER_ENVIRONMENT/, /RUNNER_OS/, /New-LocalUser/,
    /Start-Process/, /-Credential/, /SetAccessRuleProtection/,
    /S-1-5-32-544/, /Remove-LocalUser/, /Get-FileHash/,
    /replay/, /attacker/, /finally/,
  ]) assert.match(script, required);
});
