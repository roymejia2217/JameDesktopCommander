import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const workflow = fs.readFileSync(path.join(repo,
  '.github/workflows/t011-capability-feasibility.yml'), 'utf8');
const linux = 'test/security/t011-linux-storage-domain-acceptance.sh';
const windows = 'test/security/t011-windows-storage-domain-acceptance.ps1';

test('cross-volume custody exercises real OS fixtures on both hosted platforms', () => {
  for (const [script, invocation] of [
    [linux, 'bash test/security/t011-linux-storage-domain-acceptance.sh'],
    [windows, 'pwsh -NoProfile -File test/security/t011-windows-storage-domain-acceptance.ps1'],
  ]) {
    assert.ok(fs.existsSync(path.join(repo, script)), `missing ${script}`);
    assert.ok(workflow.includes(invocation), `native CI must execute ${invocation}`);
  }
});
test('cross-volume proof includes positive links, genuine denials and outside integrity', () => {
  for (const source of [linux, windows]) {
    const content = fs.readFileSync(path.join(repo, source), 'utf8');
    assert.match(content, /RUNNER_ENVIRONMENT/);
    assert.match(content, /SAME_VOLUME_HARDLINK_PASS/);
    assert.match(content, /CROSS_VOLUME_HARDLINK_DENIED/);
    assert.match(content, /EXTERIOR_BYTES_UNCHANGED/);
    assert.doesNotMatch(content, /continue-on-error/);
  }
});
