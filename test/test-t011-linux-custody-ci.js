import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';

const repo = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(
  path.join(repo, '.github/workflows/t011-capability-feasibility.yml'), 'utf8',
).replace(/\r\n/g, '\n');

test('Linux custody acceptance runs within the native security matrix', () => {
  assert.match(workflow, /^  native-probe:\n/m);
  assert.match(workflow, /^          - runner: ubuntu-24\.04\n            target: linux-x64$/m);
  assert.doesNotMatch(workflow, /^  linux-custody-acceptance:/m,
    'a detached optional job must not be mistaken for an already-governed native gate');

  const steps = YAML.parse(workflow).jobs['native-probe'].steps;
  for (const [id, command] of [
    ['linux_identity_fixture',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-service/Cargo.toml'],
    ['linux_store_fixture',
      'cargo +1.91.1 build --locked --examples --manifest-path native/authority-store/Cargo.toml'],
    ['linux_custody_lint',
      'shellcheck --severity=warning test/security/t011-linux-custody-acceptance.sh && bash -n test/security/t011-linux-custody-acceptance.sh'],
    ['linux_custody_acceptance', 'bash test/security/t011-linux-custody-acceptance.sh'],
  ]) {
    const step = steps.find(item => item.id === id);
    assert.ok(step, `Missing mandatory Linux custody gate: ${id}`);
    assert.equal(step.if, "matrix.target == 'linux-x64'");
    assert.equal(step.run, command);
  }
  const ordered = ['linux_identity_fixture', 'linux_store_fixture',
    'linux_custody_lint', 'linux_custody_acceptance'];
  assert.deepEqual(ordered.map(id => steps.findIndex(step => step.id === id)),
    [...ordered.map(id => steps.findIndex(step => step.id === id))].sort((a, b) => a - b));
  const script = fs.readFileSync(
    path.join(repo, 'test/security/t011-linux-custody-acceptance.sh'), 'utf8',
  );
  for (const expression of [
    /set -euo pipefail/, /RUNNER_ENVIRONMENT/, /getent passwd jdc-authority/,
    /sudo -n -u nobody/, /sudo -n -u jdc-authority/,
    /expect_denied replay/, /sha256sum/, /verify-2/,
    /setpriv --reuid/, /E_CUSTODY_GROUP_INJECTION_NOT_PROVEN/,
    /E_CUSTODY_SUPPLEMENTARY_GROUP_ACCEPTED/,
  ]) {
    assert.match(script, expression);
  }
});
