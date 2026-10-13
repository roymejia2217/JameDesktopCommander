import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/t011-capability-feasibility.yml'), 'utf8').replace(/\r\n/g, '\n');
test('Windows custody test belongs to the governed existing native matrix', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.match(workflow, /- runner: windows-2025\n            target: win32-x64/);
  assert.doesNotMatch(workflow, /^  windows-custody-acceptance:/m);
  for (const [title, command] of [
    ['Build test-only Windows custody fixtures',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml'],
    ['Prove Windows distinct-principal NTFS custody and reject rollback',
      'pwsh -NoProfile -File test/security/t011-windows-custody-acceptance.ps1'],
  ]) {
    assert.ok(workflow.includes(`      - name: ${title}\n        if: matrix.target == 'win32-x64'\n        run: ${command}`),
      `Missing mandatory Windows native gate: ${title}`);
  }
  const script = fs.readFileSync(path.join(root, 'test/security/t011-windows-custody-acceptance.ps1'), 'utf8');
  for (const required of [
    /GITHUB_ACTIONS/, /RUNNER_ENVIRONMENT/, /RUNNER_OS/, /New-LocalUser/,
    /Start-Process/, /-Credential/, /SetAccessRuleProtection/,
    /S-1-5-32-544/, /Remove-LocalUser/, /Get-FileHash/,
    /replay/, /attacker/, /finally/,
  ]) assert.match(script, required);
});
