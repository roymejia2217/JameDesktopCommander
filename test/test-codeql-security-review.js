import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';

const workflow = parse(fs.readFileSync(
  path.resolve(import.meta.dirname, '../.github/workflows/codeql.yml'), 'utf8',
), { uniqueKeys: true });
const actionSha = '2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2';
const checkoutSha = 'd23441a48e516b6c34aea4fa41551a30e30af803';
const languageExpression = String.fromCharCode(36) + '{{ matrix.language }}';

function validateSecurityReview(candidate) {
  assert.equal(candidate.jobs.analyze.name, 'CodeQL',
    'preserve existing JS/TS scanning and protected check identity');
  const job = candidate.jobs['security-review'];
  assert.ok(job, 'require a separate CodeQL security-review job');
  assert.equal(job['runs-on'], 'ubuntu-24.04');
  assert.equal(job['timeout-minutes'], 30);
  assert.equal(job['strategy']['fail-fast'], false);
  assert.deepEqual([...job.strategy.matrix.language].sort(), ['actions', 'rust']);
  assert.deepEqual(job.permissions, {
    contents: 'read', 'security-events': 'write',
  });
  assert.equal(job.steps.length, 3);
  const [checkout, init, analyze] = job.steps;
  assert.equal(checkout.uses, 'actions/checkout@' + checkoutSha);
  assert.equal(checkout.with['persist-credentials'], false);
  assert.equal(init.uses, 'github/codeql-action/init@' + actionSha);
  assert.equal(init.with.languages, languageExpression);
  assert.equal(init.with['build-mode'], 'none');
  assert.equal(init.with.queries, 'security-extended');
  assert.equal(analyze.uses, 'github/codeql-action/analyze@' + actionSha);
  assert.equal(analyze.with.category, '/language:' + languageExpression);
  assert.ok(!job.steps.some(s => /upload-artifact|curl|Invoke-WebRequest/i.test(
    String(s.uses ?? '') + String(s.run ?? ''))));
}

test('independent CodeQL Rust and Actions review is pinned and fail-closed', () => {
  validateSecurityReview(workflow);
});
test('review rejects loss of language coverage', () => {
  const changed = structuredClone(workflow);
  changed.jobs['security-review'].strategy.matrix.language = ['rust'];
  assert.throws(() => validateSecurityReview(changed));
});
test('review rejects reduced query depth', () => {
  const changed = structuredClone(workflow);
  changed.jobs['security-review'].steps[1].with.queries = 'default';
  assert.throws(() => validateSecurityReview(changed));
});
test('review rejects action supply-chain downgrade', () => {
  const changed = structuredClone(workflow);
  changed.jobs['security-review'].steps[1].uses = 'github/codeql-action/init@v4';
  assert.throws(() => validateSecurityReview(changed));
});
test('review rejects token permission escalation', () => {
  const changed = structuredClone(workflow);
  changed.jobs['security-review'].permissions.contents = 'write';
  assert.throws(() => validateSecurityReview(changed));
});
