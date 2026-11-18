import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const policy = JSON.parse(readFileSync(
  new URL('../.github/rulesets/main-protection.json', import.meta.url), 'utf8',
));
const rule = type => policy.rules.find(candidate => candidate.type === type);

test('versioned main ruleset retains all enforced required CI and CodeQL contexts', () => {
  assert.equal(policy.name, 'main-protection');
  assert.equal(policy.target, 'branch');
  assert.equal(policy.enforcement, 'active');
  assert.deepEqual(policy.conditions.ref_name, { exclude: [], include: ['~DEFAULT_BRANCH'] });
  const checks = rule('required_status_checks')?.parameters;
  assert.equal(checks?.strict_required_status_checks_policy, true);
  assert.equal(checks?.do_not_enforce_on_create, false);
  assert.deepEqual(checks.required_status_checks.map(check => check.context), [
    'PR Governance', 'Required CI', 'CodeQL Security (rust)', 'CodeQL Security (actions)',
  ]);
});

test('versioned main ruleset keeps zero bypasses, protected squash and CodeQL gate', () => {
  assert.deepEqual(policy.bypass_actors, []);
  for (const type of ['deletion', 'non_fast_forward', 'required_linear_history']) {
    assert.ok(rule(type), `missing main-protection rule: ${type}`);
  }
  assert.deepEqual(rule('pull_request').parameters.allowed_merge_methods, ['squash']);
  assert.equal(rule('pull_request').parameters.required_review_thread_resolution, true);
  assert.deepEqual(rule('code_scanning').parameters.code_scanning_tools, [{
    tool: 'CodeQL', security_alerts_threshold: 'high_or_higher', alerts_threshold: 'errors',
  }]);
});
