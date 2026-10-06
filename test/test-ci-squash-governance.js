#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, '..');
const workflowPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(repositoryRoot, '.github', 'workflows', 'ci.yml');

const workflow = YAML.parse(fs.readFileSync(workflowPath, 'utf8'));
const steps = workflow.jobs?.['required-ci']?.steps ?? [];
const defaultsIndex = steps.findIndex(
  (step) => step.name === 'Validate repository squash defaults',
);
const prospectiveIndex = steps.findIndex(
  (step) => step.name === 'Validate prospective squash commit',
);

assert.ok(defaultsIndex >= 0, 'CI must validate repository squash defaults');
assert.ok(prospectiveIndex >= 0, 'CI must validate the prospective squash commit');
assert.ok(
  defaultsIndex < prospectiveIndex,
  'repository squash defaults must be validated before prospective commit metadata',
);
const defaultsStep = steps[defaultsIndex];
assert.equal(
  defaultsStep.if,
  "github.event_name == 'pull_request'",
  'squash-default validation must run for pull requests only',
);
assert.match(
  defaultsStep.uses ?? '',
  /^actions\/github-script@[0-9a-f]{40}$/,
  'github-script must be pinned to a full commit SHA',
);

const script = defaultsStep.with?.script ?? '';
for (const fragment of [
  'squashMergeAllowed',
  'mergeCommitAllowed',
  'rebaseMergeAllowed',
  'squashMergeCommitTitle',
  'squashMergeCommitMessage',
  "squashMergeAllowed: true",
  "mergeCommitAllowed: false",
  "rebaseMergeAllowed: false",
  "squashMergeCommitTitle: 'PR_TITLE'",
  "squashMergeCommitMessage: 'BLANK'",
]) {
  assert.ok(script.includes(fragment), `missing squash-default assertion: ${fragment}`);
}

assert.match(script, /github\.graphql\(/, 'CI must read live repository settings through GraphQL');
assert.doesNotMatch(
  script,
  /github\.rest\.repos\.get\(/,
  'CI must not rely on REST merge settings omitted by the Actions token',
);
assert.match(script, /core\.setFailed\(/, 'CI must fail closed on repository drift');

console.log('CI squash governance contract: PASS');
