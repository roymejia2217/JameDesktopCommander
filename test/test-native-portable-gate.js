import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = YAML.parse(fs.readFileSync(
  path.join(root, '.github/workflows/distribution-candidate.yml'), 'utf8'));

test('every Windows/Linux candidate requires a locked native addon', () => {
  assert.equal(workflow.env?.JDC_CANDIDATE_INCLUDE_NATIVE, '1');
  const job = workflow.jobs?.['portable-candidate'];
  const platforms = job?.strategy?.matrix?.include ?? [];
  assert.deepEqual(platforms.map(p => p.target).sort(), ['linux-x64', 'win32-x64']);
  const steps = job?.steps ?? [];
  function findStep(label) {
    const index = steps.findIndex(step => step.name === label);
    assert.notEqual(index, -1, 'Missing required native packaging gate: ' + label);
    return index;
  }
  const lock = findStep('Verify committed native dependency lock');
  const build = findStep('Compile platform-specific capability addon from locked source');
  const check = findStep('Exercise real native confinement and create verified Node addon');
  const stage = findStep('Stage Node runtime and native capability with hashed manifest');
  const verify = findStep('Independently verify staged bytes and provenance');
  const smoke = findStep('Smoke test packaged Node and bundled ripgrep');
  const roundtrip = findStep('Verify downloaded TAR and smoke extracted native runtime');
  assert.ok(lock < build && build < check && check < stage &&
    stage < verify && verify < smoke && smoke < roundtrip,
  'Native validation and full staged/roundtrip acceptance must run in that order');
  assert.match(steps[build].run, /cargo \+1\.91\.1 build --locked --release/);
  assert.match(steps[check].run, /test\/security\/capability-namespace-swap\.test\.cjs/);
  assert.match(steps[stage].run, /distribution-candidate\.mjs build/);
  assert.match(steps[roundtrip].run, /distribution-candidate\.mjs roundtrip/);
});
