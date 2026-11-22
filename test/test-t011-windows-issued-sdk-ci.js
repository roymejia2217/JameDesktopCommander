import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import YAML from 'yaml';

test('Windows native security CI executes the issued MCP SDK custody proof', () => {
  const workflow = YAML.parse(readFileSync('.github/workflows/t011-capability-feasibility.yml', 'utf8'),
    { uniqueKeys: true });
  const steps = workflow.jobs['native-probe'].steps;
  const index = (id) => steps.findIndex((step) => step.id === id);
  const native = index('windows_issued_sdk_native_read');
  const installed = index('windows_issued_sdk_dependencies');
  const node = steps.findIndex((step) => step.name === 'Use official Node 24');
  assert.ok(node >= 0 && installed > node && native > installed,
    'test must run after official Node 24 and locked SDK installation');
  assert.equal(steps[installed].if, "matrix.target == 'win32-x64'");
  assert.equal(steps[native].if, "matrix.target == 'win32-x64'");
  assert.match(steps[installed].run, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(steps[native].run, /JDC_T011_NODE_BINARY/);
  assert.match(steps[native].run, /--test windows_guarded_client_pipe/);
  assert.match(steps[native].run,
    /protected_issued_sdk_read_preserves_exact_bytes_and_rejects_same_sid/);
  assert.match(steps[native].run, /--ignored --exact --nocapture/);
});
