#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

function duplicateNames(names) {
  const seen = new Set();
  const duplicates = new Set();
  for (const name of names) {
    if (seen.has(name)) duplicates.add(name);
    seen.add(name);
  }
  return [...duplicates].sort();
}

async function manifestToolNames() {
  const [template, packageText] = await Promise.all([
    readFile(join(rootDir, 'manifest.template.json'), 'utf8'),
    readFile(join(rootDir, 'package.json'), 'utf8'),
  ]);
  const packageJson = JSON.parse(packageText);
  const manifest = JSON.parse(template.replace('{{VERSION}}', packageJson.version));

  if (!Array.isArray(manifest.tools)) {
    throw new TypeError('manifest.template.json must contain a tools array');
  }

  return manifest.tools.map((tool) => tool?.name).filter((name) => typeof name === 'string');
}

function inspectorToolNames(payload) {
  const tools = payload?.result?.tools;
  if (!Array.isArray(tools)) {
    throw new TypeError('MCP Inspector JSON must contain result.tools');
  }

  return tools.map((tool) => tool?.name).filter((name) => typeof name === 'string');
}

const inspectorText = await readStdin();
if (!inspectorText) {
  throw new Error('Expected MCP Inspector JSON on stdin');
}

const inspectorPayload = JSON.parse(inspectorText);
const [manifestNames, serverNames] = await Promise.all([
  manifestToolNames(),
  Promise.resolve(inspectorToolNames(inspectorPayload)),
]);

const manifestDuplicates = duplicateNames(manifestNames);
const serverDuplicates = duplicateNames(serverNames);
const manifestSet = new Set(manifestNames);
const serverSet = new Set(serverNames);
const missingInManifest = [...serverSet].filter((name) => !manifestSet.has(name)).sort();
const missingInServer = [...manifestSet].filter((name) => !serverSet.has(name)).sort();

if (
  manifestDuplicates.length > 0 ||
  serverDuplicates.length > 0 ||
  missingInManifest.length > 0 ||
  missingInServer.length > 0
) {
  console.error(JSON.stringify({
    manifestDuplicates,
    serverDuplicates,
    missingInManifest,
    missingInServer,
  }, null, 2));
  process.exitCode = 1;
} else {
  console.log(`Tool synchronization contract: PASS (${manifestNames.length}/${serverNames.length})`);
}
