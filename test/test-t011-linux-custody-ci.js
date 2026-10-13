import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(
  path.join(repo, '.github/workflows/t011-capability-feasibility.yml'), 'utf8',
).replace(/\r\n/g, '\n');

test('cross-principal proof is inside the existing governed Linux native job', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.match(workflow, /^          - runner: ubuntu-24\.04\n            target: linux-x64$/m);
  assert.doesNotMatch(workflow, /^  linux-custody-acceptance:/m,
    'a detached optional job must not be mistaken for an already-governed native gate');

  for (const [name, command] of [
    ['Build test-only dedicated identity probe on Linux',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-service/Cargo.toml'],
    ['Build test-only transactional store fixture on Linux',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml'],
    ['Lint Linux cross-principal acceptance fixture',
      'shellcheck --severity=warning test/security/t011-linux-custody-acceptance.sh && bash -n test/security/t011-linux-custody-acceptance.sh'],
    ['Prove Linux distinct-principal custody and reject database rollback',
      'bash test/security/t011-linux-custody-acceptance.sh'],
  ]) {
    assert.ok(workflow.includes(`      - name: ${name}\n        if: matrix.target == 'linux-x64'\n        run: ${command}`),
      `Linux-only native control missing or conditional check removed: ${name}`);
  }
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-custody-acceptance.sh'), 'utf8',
  );
  for (const expression of [
    /set -euo pipefail/, /RUNNER_ENVIRONMENT/, /useradd --system/,
    /sudo -n -u nobody/, /sudo -n -u jdc-authority/,
    /expect_denied replay/, /sha256sum/, /verify-2/,
  ]) {
    assert.match(script, expression);
  }
});
