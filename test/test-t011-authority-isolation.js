import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const sourceRoot = path.join(repositoryRoot, 'src');

// Only the existing, explicitly NON-AUTHORIZING definitions are exempt.
// Production tools, transport, services, widgets and newly added modules
// must not promote these prototypes into executable authorization paths.
const definitionOnly = new Set([
  'src/config-manager.ts',
  'src/security/filesystem-policy-snapshot.ts',
  'src/security/filesystem-policy-generation.ts',
]);
const forbiddenSymbols = new Set([
  'RootCapability',
  'RestrictedCapabilityPolicy',
]);
const forbiddenMethodCalls = new Set([
  'getFilesystemPolicyCandidateSnapshot',
  'setFilesystemPolicyCooperatively',
]);

function listSourceFiles(root) {
  const result = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) result.push(...listSourceFiles(full));
    else if (entry.isFile() && /\.(?:[cm]?ts|tsx|[cm]?js|jsx)$/.test(entry.name)) {
      result.push(full);
    }
  }
  return result;
}

function unsafeReferences(source, filename = 'fixture.ts') {
  const ast = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true);
  assert.deepEqual(ast.parseDiagnostics, [], 'Source must be parsable');
  const errors = [];

  function visit(node) {
    if (ts.isIdentifier(node) &&
        (forbiddenSymbols.has(node.text) || forbiddenMethodCalls.has(node.text))) {
      errors.push(`Experimental authority reference: ${node.text}`);
    }
    if (ts.isElementAccessExpression(node) && node.argumentExpression &&
        ts.isStringLiteralLike(node.argumentExpression) &&
        forbiddenMethodCalls.has(node.argumentExpression.text)) {
      errors.push(`Computed experimental authority reference: ${node.argumentExpression.text}`);
    }

    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isPropertyAccessExpression(callee) &&
          forbiddenMethodCalls.has(callee.name.text)) {
        errors.push(`Production invocation of policy candidate API: ${callee.name.text}`);
      }
      if (ts.isElementAccessExpression(callee) &&
          callee.argumentExpression &&
          ts.isStringLiteralLike(callee.argumentExpression) &&
          forbiddenMethodCalls.has(callee.argumentExpression.text)) {
        errors.push(`Computed production invocation of policy candidate API: ${callee.argumentExpression.text}`);
      }
    }

    if (ts.isStringLiteralLike(node) &&
        /(?:native[\\/]capability-probe|restricted-capability-policy\.cjs|jdc-capability-probe\.node|jdc_capability_probe)/i.test(node.text)) {
      errors.push('Runtime reference to experimental native capability package');
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
  return errors;
}

test('authority isolation gate detects direct, computed and native binding usage', () => {
  const maliciousExamples = [
    'new RootCapability("/tmp")',
    'new RestrictedCapabilityPolicy({})',
    'manager.getFilesystemPolicyCandidateSnapshot()',
    'manager["setFilesystemPolicyCooperatively"]([])',
    'const invoke = manager.getFilesystemPolicyCandidateSnapshot; invoke()',
    'const invoke = manager["getFilesystemPolicyCandidateSnapshot"]; invoke()',
    'const { setFilesystemPolicyCooperatively: invoke } = manager; invoke([])',
    'import { getFilesystemPolicyCandidateSnapshot as invoke } from "./config-manager.js"',
    'import("../native/capability-probe/src/lib.rs")',
    'require("../test/security/support/restricted-capability-policy.cjs")',
    'import("./target/release/jdc-capability-probe.node")',
  ];
  for (const example of maliciousExamples) {
    assert.ok(unsafeReferences(example).length > 0,
      `Gate missed a known unauthorized reference: ${example}`);
  }
  assert.deepEqual(unsafeReferences('const value = "ordinary filesystem handler";'), []);
});

test('production TypeScript/JavaScript does not use experimental capabilities as authority', () => {
  const sources = listSourceFiles(sourceRoot);
  assert.ok(sources.length >= 100, 'Source inventory unexpectedly incomplete');
  const violations = [];

  for (const absolute of sources) {
    const relative = path.relative(repositoryRoot, absolute).split(path.sep).join('/');
    if (definitionOnly.has(relative)) continue;
    const source = fs.readFileSync(absolute, 'utf8');
    for (const error of unsafeReferences(source, absolute)) {
      violations.push(`${relative}: ${error}`);
    }
  }
  assert.deepEqual(violations, [],
    'A production path began using an experimental authority; require a separate verified security migration PR');
});
