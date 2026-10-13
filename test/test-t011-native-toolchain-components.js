import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const workflowPath = path.resolve(import.meta.dirname, '../.github/workflows/t011-capability-feasibility.yml');

test('native Windows/Linux CI installs Clippy for the same pinned minimal Rust toolchain', () => {
  const workflow = fs.readFileSync(workflowPath, 'utf8');
  const install = workflow.match(/^\s*run: rustup toolchain install (\d+\.\d+\.\d+) --profile minimal(?: --component ([a-z,-]+))?\s*$/m);
  const lint = workflow.match(/^\s*run: cargo \+(\d+\.\d+\.\d+) clippy --locked --all-targets\b/m);
  assert.ok(install, 'native CI must install a pinned minimal Rust toolchain');
  assert.ok(lint, 'native CI must enforce Clippy over the same pinned toolchain');
  assert.equal(install[1], lint[1], 'Clippy and compiler must have the same pinned toolchain version');
  assert.ok(install[2]?.split(',').includes('clippy'),
    'rustup minimal does not install Clippy; the component must be declared explicitly');
});
