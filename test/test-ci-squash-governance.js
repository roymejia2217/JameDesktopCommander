#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
const contributing = fs.readFileSync(
  path.join(repositoryRoot, 'CONTRIBUTING.md'),
  'utf8',
);
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
const prospectiveStep = steps[prospectiveIndex];
assert.equal(
  prospectiveStep.if,
  "github.event_name == 'pull_request'",
  'the final squash subject must be checked on every PR',
);
assert.equal(
  prospectiveStep.env?.PR_TITLE,
  '${{ github.event.pull_request.title }}',
);
assert.equal(
  prospectiveStep.env?.PR_NUMBER,
  '${{ github.event.pull_request.number }}',
);
assert.equal(
  prospectiveStep.run?.trim(),
  `printf '%s (#%s)\\n' "$PR_TITLE" "$PR_NUMBER" | npm run --silent lint:commit`,
  'prospective lint must include the GitHub-generated PR-number suffix',
);

// Regression: #81 passed the former PR-title-only check, but its squash
// subject was 73 characters and failed on protected main.
const historicalPrTitle =
  'test(process): synchronize child readiness before output assertions';
const historicalSquashSubject = `${historicalPrTitle} (#81)`;
assert.ok(historicalPrTitle.length <= 72);
assert.equal(historicalSquashSubject.length, 73);

// Execute the repository's pinned Commitlint CLI against both subjects.
// A PR-title-only check previously passed; the actual squash subject must
// fail before merge with exactly the same rule that protects main.
const lintSubject = (subject) => {
  const result = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'node_modules', '@commitlint', 'cli', 'cli.js'),
      '--config', path.join(repositoryRoot, 'commitlint.config.cjs')],
    {
      cwd: repositoryRoot,
      input: `${subject}\n`,
      encoding: 'utf8',
      windowsHide: true,
      timeout: 15_000,
    },
  );
  assert.ifError(result.error);
  return result;
};
assert.equal(lintSubject(historicalPrTitle).status, 0);
const rejected = lintSubject(historicalSquashSubject);
assert.equal(rejected.status, 1, 'the #81 postmerge subject must be rejected premerge');
assert.match(
  rejected.stdout + rejected.stderr,
  /header must not be longer than 72 characters/i,
);
assert.equal(
  lintSubject('ci(governance): validate squash title suffix (#82)').status,
  0,
  'an appropriately short squash title must pass',
);

// A valid Commitlint body can still violate the protected squash contract.
// The protected-branch push must reject any nonblank body, even a short one.
const protectedBodyIndex = steps.findIndex(
  (step) => step.name === 'Require blank protected squash body',
);
const protectedCommitIndex = steps.findIndex(
  (step) => step.name === 'Validate protected-branch commit',
);
assert.ok(protectedBodyIndex >= 0, 'CI must reject nonblank protected squash bodies');
assert.ok(protectedCommitIndex > protectedBodyIndex, 'blank-body gate must precede Commitlint');
const protectedBodyStep = steps[protectedBodyIndex];
assert.equal(protectedBodyStep.if, "github.event_name == 'push'");
assert.match(protectedBodyStep.run, /git log -1 --format=%b/);
assert.match(protectedBodyStep.run, /\[ -n "\$body" \]/);
assert.match(protectedBodyStep.run, /exit 1/);
assert.match(protectedBodyStep.run, /::error::/);

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

assert.match(
  contributing,
  /squash commit message must remain blank/i,
  'CONTRIBUTING.md must require an empty squash commit body',
);
assert.match(
  contributing,
  /must not override the squash commit message/i,
  'CONTRIBUTING.md must forbid manual squash commit-message overrides',
);
assert.doesNotMatch(
  contributing,
  /pull-request body as the squash commit message/i,
  'CONTRIBUTING.md must not claim that the PR body becomes the squash commit body',
);

console.log('CI squash governance contract: PASS');
