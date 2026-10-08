import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..', '..');
const contract = JSON.parse(readFileSync(join(root, 'contracts', 'opencode-gateway.json'), 'utf8'));

function calls(sourceText, filename, method, argumentIndex) {
  const ast = ts.createSourceFile(filename, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const found = [];
  const visit = (node) => {
    if (ts.isCallExpression(node) && node.arguments.length > argumentIndex &&
      ((ts.isIdentifier(node.expression) && node.expression.text === method) ||
        (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === method))) {
      const argument = node.arguments[argumentIndex];
      if (!ts.isStringLiteral(argument)) {
        throw new Error('Dynamic MCP tool selection is not allowed: ' + method);
      }
      found.push(argument.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return [...new Set(found)].sort();
}

test('public interoperability contract has a reviewed immutable baseline', () => {
  assert.equal(contract.formatVersion, 1);
  assert.equal(contract.repository, 'roymejia2217/chatgpt-opencode-mcp');
  assert.match(contract.sourceCommit, /^[a-f0-9]{40}$/);
  assert.equal(contract.transportPath, '/rdc-mcp');
  assert.equal(contract.requiredTools.length, 10);
  assert.deepEqual(contract.requiredTools, [...new Set(contract.requiredTools)].sort());
});

test('JDC client calls exactly the reviewed public MCP tool surface', () => {
  const clientPath = join(root, 'src', 'tools', 'opencode.ts');
  const source = readFileSync(clientPath, 'utf8');
  assert.deepEqual(calls(source, clientPath, 'callGateway', 1), contract.requiredTools);
  assert.ok(source.includes("url.pathname !== '/rdc-mcp'"));
});

test('contract cannot authorize a caller-selected working directory', () => {
  assert.ok(!contract.requiredTools.includes('arbitrary_directory'));
  assert.ok(!contract.requiredTools.includes('set_working_directory'));
});
