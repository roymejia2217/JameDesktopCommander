'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/distribution-candidate.yml'), 'utf8');
const candidate = fs.readFileSync(path.join(root, 'scripts/distribution-candidate.mjs'), 'utf8');
const nativeWorkflow = fs.readFileSync(path.join(root, '.github/workflows/t011-capability-feasibility.yml'), 'utf8');

test('portable package never opts into the unapproved N-API binary', () => {
  assert.match(workflow, /^\s+JDC_CANDIDATE_INCLUDE_NATIVE: '0'$/m);
  assert.doesNotMatch(workflow, /^\s+JDC_CANDIDATE_INCLUDE_NATIVE: '1'$/m);
  assert.match(workflow, /\bCompile deny-only native addon from locked source\b/);
  assert.match(workflow, /\bVerify deny-only native addon surface before staging\b/);
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

test('separate T011 native feasibility CI still tests deny-only exports across Node versions', () => {
  assert.match(nativeWorkflow, /Verify deny-only native exports on Node 22\.19/);
  assert.match(nativeWorkflow, /Verify deny-only native exports on Node 24/);
  assert.match(nativeWorkflow, /capability-default-surface\.test\.cjs/);
});
