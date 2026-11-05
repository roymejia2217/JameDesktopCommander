import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = name => JSON.parse(readFileSync(join(root, name), 'utf8'));
const pkg = read('package.json');
const lock = read('package-lock.json');
const server = read('server.json');
const repository = 'https://github.com/roymejia2217/JameDesktopCommander';
const packageName = '@roymejia2217/jame-desktop-commander';
const mcpName = 'io.github.roymejia2217/jame-desktop-commander';

test('private JDC identity is coherent without asserting npm namespace control', () => {
  assert.equal(pkg.name, packageName);
  assert.equal(lock.name, packageName);
  assert.equal(lock.packages[''].name, packageName);
  assert.equal(pkg.private, true, 'npm publication requires separate owner approval');
  assert.equal(pkg.repository.url, repository + '.git');
  assert.equal(pkg.homepage, repository);
  assert.equal(pkg.bugs, repository + '/issues');
  assert.equal(pkg.mcpName, mcpName);
});
test('MCP server no longer advertises an unowned upstream npm install', () => {
  assert.equal(server.name, mcpName);
  assert.equal(server.repository.url, repository);
  assert.equal(server.repository.source, 'github');
  assert.equal(server.title, 'JameDesktopCommander');
  assert.equal(server.version, pkg.version);
  assert.ok(!Object.hasOwn(server, 'packages') || server.packages.length === 0,
    'Private source must not advertise an unverified npm registry package');
});
test('inherited MIT copyright and upstream author credit remain intact', () => {
  const license = readFileSync(join(root, 'LICENSE'), 'utf8');
  assert.match(license, /MIT License/);
  assert.match(license, /Eduard Ruzga and Desktop Commander Contributors/);
});
test('production release identity remains fail-closed for private staging', async () => {
  const { verifyReleaseIdentity } = await import('../scripts/verify-release-identity.mjs');
  const manifest = read('.release-please-manifest.json');
  assert.throws(() => verifyReleaseIdentity({
    pkg, server, manifest, expectedRepository: 'roymejia2217/JameDesktopCommander',
  }), /E_RELEASE_IDENTITY_REGISTRY_NOT_PUBLISHABLE/);
});
