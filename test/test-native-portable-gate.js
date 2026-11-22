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
function position(steps, id) {
  const index = steps.findIndex(step => step.id === id);
  assert.notEqual(index, -1, 'Missing enforced workflow step: ' + id);
  return index;
}
function assertNoResearchBuild(steps) {
  for (const step of steps) {
    assert.doesNotMatch(step.run ?? '', /receiver-test-fixture|--features|research_impl/,
      'A released native binary may not compile research-only FFI');
  }
}
test('portable distribution excludes native authority and retains separate security acceptance', () => {
  const config = workflow('distribution-candidate.yml');
  const producer = config.jobs['portable-candidate'];
  const consumer = config.jobs['portable-acceptance'];
  assert.equal(config.env?.JDC_CANDIDATE_INCLUDE_NATIVE, '0');
  assert.deepEqual(producer.strategy.matrix.include.map(p => p.target).sort(),
    ['linux-x64', 'win32-x64']);
  assert.deepEqual(consumer.strategy.matrix, producer.strategy.matrix);
  assert.deepEqual(consumer.needs,
    ['portable-candidate', 'windows-operator-ui', 'linux-operator-ui']);
  const producerSteps = producer.steps;
  const stageIds = ['portable_stage', 'portable_stage_integrity', 'portable_smoke'];
  const indices = stageIds.map(id => position(producerSteps, id));
  for (const [index, command] of indices.map((index, i) => [index, ['build', 'verify', 'smoke'][i]])) {
    assert.equal(producerSteps[index].run, `node scripts/distribution-candidate.mjs ${command}`);
  }
  assert.deepEqual(indices, [...indices].sort((a, b) => a - b),
    'Authorization, packaging and exact-archive checks must retain order');
  const consumerSteps = consumer.steps;
  const downloaded = position(consumerSteps, 'portable_download');
  const verify = position(consumerSteps, 'portable_roundtrip');
  assert.match(consumerSteps[downloaded].uses, /^actions\/download-artifact@/);
  assert.ok(downloaded < verify, 'the original uploaded archive must be validated before extraction');
  assert.match(consumerSteps[verify].run, /distribution-candidate\.mjs roundtrip/);
  for (const steps of [producerSteps, consumerSteps]) {
    assertNoResearchBuild(steps);
    assert.ok(steps.every(step => !/\b(?:cargo|rustup)\b/.test(step.run ?? '')),
      'Portable distribution must not build experimental Rust authority');
    assert.ok(steps.every(step =>
      !/native addon from locked source|native dependency lock|native addon surface before staging/i.test(step.name ?? '')),
    'Native ownership proofs belong only to dedicated T011 feasibility CI');
  }
});
test('native security matrix checks API denial across supported Node versions', () => {
  const job = workflow('t011-capability-feasibility.yml').jobs['native-probe'];
  assert.deepEqual(job.strategy.matrix.include.map(p => p.target).sort(),
    ['linux-x64', 'win32-x64']);
  const steps = job.steps;
  assertNoResearchBuild(steps);
  for (const nodeVersion of ['22.19', '24']) {
    const id = nodeVersion === '22.19' ? 'native_api_node22' : 'native_api_node24';
    const index = position(steps, id);
    assert.match(steps[index].run, /capability-default-surface\.test\.cjs/);
  }
  const linux = steps[position(steps, 'linux_custody_acceptance')];
  const windows = steps[position(steps, 'windows_custody_acceptance')];
  assert.equal(linux.if, "matrix.target == 'linux-x64'");
  assert.equal(windows.if, "matrix.target == 'win32-x64'");
  assert.match(linux.run, /bash test\/security\/t011-linux-custody-acceptance\.sh/);
  assert.match(windows.run, /pwsh -NoProfile -File test\/security\/t011-windows-custody-acceptance\.ps1/);
  assert.match(steps[position(steps, 'native_module_lint')].run, /cargo \+1\.91\.1 clippy/);
  const artifact = steps[position(steps, 'native_proof_integrity')];
  assert.match(artifact.uses, /^actions\/upload-artifact@/);
  assert.match(artifact.with.name, /^UNPUBLISHED-/);
  assert.equal(artifact.with['retention-days'], 1);
  assert.equal(artifact.with['if-no-files-found'], 'error');
});
