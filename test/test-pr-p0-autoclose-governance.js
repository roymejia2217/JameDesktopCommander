import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import YAML from 'yaml';

const workflow = YAML.parse(
  fs.readFileSync(new URL('../.github/workflows/pr-governance.yml', import.meta.url), 'utf8'),
  { uniqueKeys: true },
);
const step = workflow.jobs.governance.steps.find(
  (entry) => entry.name === 'Prevent premature P0 issue auto-closure',
);

function issue({ number = 139, state = 'OPEN', labels = ['priority:P0'] } = {}) {
  return {
    number, state, url: `https://github.com/roymejia2217/JameDesktopCommander/issues/${number}`,
    labels: { nodes: labels.map((name) => ({ name })), pageInfo: { hasNextPage: false } },
  };
}

async function exercise(issues, { truncated = false, labelTruncated = false } = {}) {
  assert.ok(step, 'the required PR Governance job must check P0 auto-closure');
  assert.match(step.uses ?? '', /^actions\/github-script@[0-9a-f]{40}$/);
  assert.equal(workflow.permissions?.issues, 'read');
  assert.equal(workflow.permissions?.['pull-requests'], 'read');
  const failures = [];
  const context = {
    repo: { owner: 'roymejia2217', repo: 'JameDesktopCommander' },
    payload: { pull_request: { number: 333 } },
  };
  const github = {
    graphql: async (query, variables) => {
      assert.match(query, /closingIssuesReferences\s*\(/);
      assert.deepEqual({ ...variables }, { owner: 'roymejia2217', name: 'JameDesktopCommander', number: 333 });
      return { repository: { pullRequest: { closingIssuesReferences: {
        nodes: issues.map((entry) => ({
          ...entry,
          labels: { ...entry.labels, pageInfo: { hasNextPage: labelTruncated } },
        })),
        pageInfo: { hasNextPage: truncated },
      } } } };
    },
  };

  const core = { setFailed: (reason) => failures.push(String(reason)) };
  await runInNewContext(`(async () => {
    ${step.with.script}
  })()`, { context, github, core }, { timeout: 2000 });
  return failures;
}

test('historical #333 linked open P0 would fail the merge gate', async () => {
  const failures = await exercise([issue()]);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /#139/);
});

test('a research PR not linked for closure remains eligible', async () => {
  assert.deepEqual(await exercise([]), []);
});

test('a linked open issue without P0 label remains eligible', async () => {
  assert.deepEqual(await exercise([issue({ number: 555, labels: ['priority:P1'] })]), []);
});

test('an already closed P0 issue does not block an unrelated PR', async () => {
  assert.deepEqual(await exercise([issue({ state: 'CLOSED' })]), []);
});

test('pagination of closing issues fails closed', async () => {
  const failures = await exercise([], { truncated: true });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /pagination|incomplete/i);
});

test('pagination of issue labels fails closed', async () => {
  const failures = await exercise([issue({ labels: ['kanban:in-progress'] })], { labelTruncated: true });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /pagination|incomplete/i);
});

test('the governance check is re-run on PR body and HEAD edits', () => {
  const types = workflow.on?.pull_request?.types ?? [];
  for (const event of ['opened', 'edited', 'reopened', 'synchronize', 'ready_for_review']) {
    assert.ok(types.includes(event), `missing PR trigger ${event}`);
  }
});
