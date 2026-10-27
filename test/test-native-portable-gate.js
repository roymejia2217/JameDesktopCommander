import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function workflow(filename) {
  return YAML.parse(fs.readFileSync(path.join(root, '.github/workflows', filename), 'utf8'));
}
function position(steps, label) {
  const index = steps.findIndex(step => step.name === label);
  assert.notEqual(index, -1, 'Missing enforced distribution step: ' + label);
  return index;
}
function assertNoResearchBuild(steps) {
  for (const step of steps) {
    assert.doesNotMatch(step.run ?? '', /receiver-test-fixture|--features|research_impl/,
      'A released native binary may not compile research-only FFI');
  }
}
test('both native candidates build only deny-by-default and verify the unpacked bytes', () => {
  const job = workflow('distribution-candidate.yml').jobs['portable-candidate'];
  assert.equal(workflow('distribution-candidate.yml').env?.JDC_CANDIDATE_INCLUDE_NATIVE, '1');
  assert.deepEqual(job.strategy.matrix.include.map(p => p.target).sort(),
    ['linux-x64', 'win32-x64']);
  const steps = job.steps;
  const labels = [
    'Verify committed native dependency lock',
    'Compile deny-only native addon from locked source',
    'Verify deny-only native addon surface before staging',
    'Stage Node runtime and native capability with hashed manifest',
    'Independently verify staged bytes and provenance',
    'Smoke test packaged Node and bundled ripgrep',
    'Verify downloaded TAR and smoke extracted native runtime',
  ];
  const indices = labels.map(label => position(steps, label));
  assert.deepEqual(indices, [...indices].sort((a, b) => a - b),
    'Authorization, packaging and exact-archive checks must retain order');
  assertNoResearchBuild(steps);
  assert.match(steps[indices[1]].run, /cargo \+1\.91\.1 build --locked --release/);
  assert.match(steps[indices[2]].run, /capability-default-surface\.test\.cjs/);
  assert.match(steps[indices.at(-1)].run, /distribution-candidate\.mjs roundtrip/);
});
test('native Windows/Linux and Node22/24 matrices reject an unsafe class export', () => {
  const job = workflow('t011-capability-feasibility.yml').jobs['native-probe'];
  assert.deepEqual(job.strategy.matrix.include.map(p => p.target).sort(),
    ['linux-x64', 'win32-x64']);
  const steps = job.steps;
  assertNoResearchBuild(steps);
  for (const nodeVersion of ['22.19', '24']) {
    const name = 'Verify deny-only native exports on Node ' + nodeVersion;
    const index = position(steps, name);
    assert.match(steps[index].run, /capability-default-surface\.test\.cjs/);
  }
  position(steps, 'Prove Linux distinct-principal custody and reject database rollback');
  position(steps, 'Prove Windows distinct-principal NTFS custody and reject rollback');
  position(steps, 'Require warning-free deny-only native module');
  position(steps, 'Preserve unpublished proof and immutable dependency lock');
});
