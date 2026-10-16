import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';

const filename = path.resolve(import.meta.dirname, '../.github/workflows/codespell.yml');
const workflow = parse(fs.readFileSync(filename, 'utf8'), { uniqueKeys: true });
const actions = [
  'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
  'codespell-project/codespell-problem-matcher@b80729f885d32f78a716c2f107b4db1025001c42',
  'codespell-project/actions-codespell@8f01853be192eb0f849a5c7d721450e7a467c579',
];

function validate(config) {
  assert.equal(config.name, 'Codespell');
  assert.deepEqual(config.permissions, { contents: 'read' });
  assert.deepEqual(config.on.push.branches, ['main']);
  assert.deepEqual(config.on.pull_request.branches, ['main']);
  assert.deepEqual(Object.keys(config.jobs), ['codespell']);
  assert.equal(config.jobs.codespell.name, 'Check for spelling errors');
  const steps = config.jobs.codespell.steps;
  assert.deepEqual(steps.map((step) => step.uses), actions);
  assert.deepEqual(steps[0].with, { 'persist-credentials': false });
  assert.ok(steps.every((step) => step.run === undefined));
}
test('Codespell actions are pinned to reviewed immutable commits', () => {
  validate(workflow);
});

for (const [name, mutate] of [
  ['unpinned checkout', (v) => { v.jobs.codespell.steps[0].uses = 'actions/checkout@v4'; }],
  ['unpinned matcher', (v) => { v.jobs.codespell.steps[1].uses = 'codespell-project/codespell-problem-matcher@v1'; }],
  ['unpinned scanner', (v) => { v.jobs.codespell.steps[2].uses = 'codespell-project/actions-codespell@v2'; }],
  ['checkout credentials retained', (v) => { v.jobs.codespell.steps[0].with = { 'persist-credentials': true }; }],
  ['workflow permissions escalated', (v) => { v.permissions.contents = 'write'; }],
  ['unexpected executing step', (v) => { v.jobs.codespell.steps.push({ run: 'echo unexpected' }); }],
]) {
  test('rejects ' + name, () => {
    const changed = structuredClone(workflow);
    mutate(changed);
    assert.throws(() => validate(changed));
  });
}
