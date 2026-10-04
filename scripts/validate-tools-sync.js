#!/usr/bin/env node
/**
 * Validate that the tools declared by the MCPB manifest source match the
 * tools exposed by the built MCP server.
 *
 * The server is queried through the official Model Context Protocol client
 * and stdio transport. This keeps the validator aligned with real MCP
 * initialization semantics instead of depending on fixed startup sleeps.
 */

import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

async function extractToolsFromManifest() {
  const bundleManifestPath = join(rootDir, 'mcpb-bundle', 'manifest.json');
  let content;

  try {
    content = await readFile(bundleManifestPath, 'utf8');
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error;

    const [template, packageContent] = await Promise.all([
      readFile(join(rootDir, 'manifest.template.json'), 'utf8'),
      readFile(join(rootDir, 'package.json'), 'utf8'),
    ]);
    const packageJson = JSON.parse(packageContent);
    content = template.replace('{{VERSION}}', packageJson.version);
  }

  const manifest = JSON.parse(content);
  return manifest.tools.map((tool) => tool.name).sort();
}

function inheritedEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter(([, value]) => value !== undefined),
  );
}

async function extractToolsFromServer() {
  const serverPath = join(rootDir, 'dist', 'index.js');
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    cwd: rootDir,
    env: inheritedEnvironment(),
    stderr: 'pipe',
  });
  const client = new Client(
    {
      name: 'validate-tools-sync',
      version: '1.0.0',
    },
    {
      capabilities: {},
    },
  );

  let stderr = '';
  transport.stderr?.on('data', (chunk) => {
    stderr += chunk.toString();
    if (stderr.length > 16_384) {
      stderr = stderr.slice(-16_384);
    }
  });

  try {
    await client.connect(transport);
    const response = await client.listTools();
    return response.tools.map((tool) => tool.name).sort();
  } catch (error) {
    const suffix = stderr.trim() ? `\nServer stderr:\n${stderr.trim()}` : '';
    throw new Error(
      `Unable to query MCP tools: ${error instanceof Error ? error.message : String(error)}${suffix}`,
      { cause: error },
    );
  } finally {
    await client.close().catch(() => {});
  }
}

async function main() {
  console.log(`${colors.cyan}Validating tool synchronization...${colors.reset}\n`);

  try {
    const [manifestTools, serverTools] = await Promise.all([
      extractToolsFromManifest(),
      extractToolsFromServer(),
    ]);

    console.log(`${colors.blue}Manifest tools (${manifestTools.length}):${colors.reset}`);
    manifestTools.forEach((tool) => console.log(`   - ${tool}`));

    console.log(`\n${colors.blue}Server tools (${serverTools.length}):${colors.reset}`);
    serverTools.forEach((tool) => console.log(`   - ${tool}`));

    const missingInManifest = serverTools.filter((tool) => !manifestTools.includes(tool));
    const missingInServer = manifestTools.filter((tool) => !serverTools.includes(tool));

    console.log('\n' + '='.repeat(60));

    if (missingInManifest.length === 0 && missingInServer.length === 0) {
      console.log(`${colors.green}SUCCESS: All tools are in sync.${colors.reset}`);
      console.log(
        `${colors.green}Manifest and server both expose ${manifestTools.length} tools.${colors.reset}`,
      );
      return;
    }

    console.log(`${colors.red}MISMATCH DETECTED${colors.reset}\n`);

    if (missingInManifest.length > 0) {
      console.log(`${colors.yellow}Tools in server but not manifest:${colors.reset}`);
      missingInManifest.forEach((tool) => console.log(`   ${colors.red}x${colors.reset} ${tool}`));
      console.log();
    }

    if (missingInServer.length > 0) {
      console.log(`${colors.yellow}Tools in manifest but not server:${colors.reset}`);
      missingInServer.forEach((tool) => console.log(`   ${colors.red}x${colors.reset} ${tool}`));
      console.log();
    }

    process.exitCode = 1;
  } catch (error) {
    console.error(
      `${colors.red}Error:${colors.reset}`,
      error instanceof Error ? error.message : String(error),
    );
    process.exitCode = 1;
  }
}

await main();
