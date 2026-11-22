'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { spawnSync } = require('node:child_process');
const YAML = require('yaml');
const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/distribution-candidate.yml'), 'utf8');
const candidate = fs.readFileSync(path.join(root, 'scripts/distribution-candidate.mjs'), 'utf8');
const nativeWorkflow = fs.readFileSync(path.join(root, '.github/workflows/t011-capability-feasibility.yml'), 'utf8');

test('portable package never opts into the unapproved N-API binary', () => {
  assert.match(workflow, /^\s+JDC_CANDIDATE_INCLUDE_NATIVE: '0'$/m);
  assert.doesNotMatch(workflow, /^\s+JDC_CANDIDATE_INCLUDE_NATIVE: '1'$/m);
  assert.doesNotMatch(workflow, /\bCompile deny-only native addon from locked source\b/);
  assert.doesNotMatch(workflow, /\bVerify deny-only native addon surface before staging\b/);
  assert.doesNotMatch(workflow, /\b(?:rustup toolchain|cargo \+1\.91\.1)\b/,
    'Portable candidate must not compile an excluded Rust addon');
  assert.doesNotMatch(workflow, /\bStage Node runtime and native capability\b/);
  assert.match(workflow, /node scripts\/distribution-candidate\.mjs verify/);
  assert.match(workflow, /node scripts\/distribution-candidate\.mjs roundtrip/);
});

test('portable runner rejects an environment override that requests a native addon', () => {
  assert.match(candidate, /assert\.notEqual\(process\.env\.JDC_CANDIDATE_INCLUDE_NATIVE,\s*'1'/);
  assert.doesNotMatch(candidate, /process\.env\.JDC_CANDIDATE_INCLUDE_NATIVE === '1'\s*\?\s*\{\s*nativeAddon/);
  assert.match(candidate, /assert\.equal\(manifest\.nativeCapabilityAddon,\s*undefined/);
});

test('portable CLI denies a real environment re-enable attempt before staging files', () => {
  const command = spawnSync(process.execPath, [
    path.join(root, 'scripts/distribution-candidate.mjs'), 'build',
  ], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10000,
    maxBuffer: 64 * 1024,
    env: { ...process.env, JDC_CANDIDATE_INCLUDE_NATIVE: '1' },
  });
  assert.equal(command.error, undefined);
  assert.equal(command.status, 1);
  assert.match(command.stderr, /Unapproved native capability addon cannot enter portable distribution/);
});

test('native security CI verifies denial on pinned Node.js 22.19 and 24 runtimes', () => {
  const steps = YAML.parse(nativeWorkflow, { uniqueKeys: true }).jobs['native-probe'].steps;
  const build = steps.findIndex(step => step.run ===
    'cargo +1.91.1 build --locked --release --manifest-path native/capability-probe/Cargo.toml');
  assert.ok(build >= 0, 'Native denial build must precede runtime verification');
  let previous = build;
  for (const [id, version] of [['native_api_node22', '22.19.0'], ['native_api_node24', 24]]) {
    const index = steps.findIndex(step => step.id === id);
    assert.ok(index > previous, `Missing ordered native API check ${id}`);
    assert.equal(steps[index].run,
      'node --test test/security/capability-default-surface.test.cjs');
    const nodeSetup = steps.findLastIndex((step, i) => i < index &&
      String(step.uses ?? '').startsWith('actions/setup-node@'));
    assert.ok(nodeSetup >= previous, `Missing pinned Node runtime before ${id}`);
    assert.equal(steps[nodeSetup].uses,
      'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38');
    assert.equal(steps[nodeSetup].with['node-version'], version);
    previous = index;
  }
});
