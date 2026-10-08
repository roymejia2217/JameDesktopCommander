import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import ts from 'typescript';

const projectRoot = resolve(import.meta.dirname, '..', '..');
const contract = JSON.parse(readFileSync(join(projectRoot, 'contracts', 'opencode-gateway.json'), 'utf8'));

function collectNamedCalls(sourceText, filename, method, argumentPosition) {
  const ast = ts.createSourceFile(filename, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      node.arguments.length > argumentPosition &&
      ((ts.isIdentifier(node.expression) && node.expression.text === method) ||
       (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === method))
    ) {
      const arg = node.arguments[argumentPosition];
      if (!ts.isStringLiteral(arg)) {
        throw new Error('Dynamic protocol tool selection is not permitted: ' + method);
      }
      found.push(arg.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return [...new Set(found)].sort();
}

test('compatibility baseline pins an immutable public Git commit', () => {
  assert.match(contract.sourceCommit, /^[0-9a-f]{40}$/);
  assert.equal(contract.repository, 'roymejia2217/chatgpt-opencode-mcp');
  assert.equal(contract.transportPath, '/rdc-mcp');
  assert.equal(contract.formatVersion, 1);
  assert.equal(contract.requiredTools.length, 10);
});

test('all gateway tools used by JDC exist in exactly the pinned gateway full MCP surface', () => {
  const gatewayRoot = process.env.JDC_GATEWAY_CHECKOUT;
  assert.ok(gatewayRoot, 'CI must supply JDC_GATEWAY_CHECKOUT from a pinned actions/checkout');
  const actualRef = execFileSync('git', ['-C', gatewayRoot, 'rev-parse', 'HEAD'], {
    encoding: 'utf8', timeout: 10_000, windowsHide: true,
  }).trim();
  assert.equal(actualRef, contract.sourceCommit, 'gateway source differs from reviewed compatibility pin');

  const gatewayPath = join(gatewayRoot, 'src', 'mcp-server.ts');
  const clientPath = join(projectRoot, 'src', 'tools', 'opencode.ts');
  const gatewayCalls = collectNamedCalls(readFileSync(gatewayPath, 'utf8'), gatewayPath, 'registerTool', 0);
  const clientCalls = collectNamedCalls(readFileSync(clientPath, 'utf8'), clientPath, 'callGateway', 1);
  assert.deepEqual(gatewayCalls, contract.requiredTools, 'gateway surface changed: review source and compatibility');
  assert.deepEqual(clientCalls, contract.requiredTools, 'JDC client tool names changed: review source and compatibility');
  assert.ok(readFileSync(clientPath, 'utf8').includes("url.pathname !== '/rdc-mcp'"));
});

test('compatibility contract rejects missing or extra tool names', () => {
  const list = contract.requiredTools;
  assert.notDeepEqual([...list.filter(x => x !== 'task_wait')], list);
  assert.ok(!list.includes('arbitrary_directory'));
  assert.deepEqual(list, [...new Set(list)].sort());
});
