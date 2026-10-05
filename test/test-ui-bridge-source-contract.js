#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(testDirectory, '..');
const companionRoot = path.join(repoRoot, 'companion', 'windows-ui');
const projectRoot = path.join(companionRoot, 'DesktopCommander.UiBridge');

const requiredFiles = [
  path.join(companionRoot, 'global.json'),
  path.join(companionRoot, 'NuGet.config'),
  path.join(projectRoot, 'DesktopCommander.UiBridge.csproj'),
  path.join(projectRoot, 'packages.lock.json'),
  path.join(projectRoot, 'Program.cs'),
  path.join(projectRoot, 'Protocol.cs'),
  path.join(projectRoot, 'NamedPipeBridgeServer.cs'),
  path.join(projectRoot, 'UiSnapshotService.cs'),
];

for (const file of requiredFiles) {
  const stat = await fs.stat(file);
  assert.equal(stat.isFile(), true, `required UI bridge source missing: ${file}`);
}

const globalJson = JSON.parse(await fs.readFile(path.join(companionRoot, 'global.json'), 'utf8'));
assert.equal(globalJson.sdk?.version, '10.0.401');
assert.equal(globalJson.sdk?.rollForward, 'disable');
assert.equal(globalJson.sdk?.allowPrerelease, false);

const project = await fs.readFile(
  path.join(projectRoot, 'DesktopCommander.UiBridge.csproj'),
  'utf8',
);

for (const contract of [
  '<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework>',
  '<RuntimeIdentifier>win-x64</RuntimeIdentifier>',
  '<SelfContained>true</SelfContained>',
  '<PublishSingleFile>true</PublishSingleFile>',
  '<EnableWindowsTargeting>true</EnableWindowsTargeting>',
  '<TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
  '<Deterministic>true</Deterministic>',
  '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>',
]) {
  assert.ok(project.includes(contract), `UI bridge project contract missing: ${contract}`);
}

const lock = JSON.parse(await fs.readFile(path.join(projectRoot, 'packages.lock.json'), 'utf8'));
const tfm = lock.dependencies?.['net10.0-windows10.0.19041'];
assert.ok(tfm, 'UI bridge lockfile must contain the Windows target framework');
assert.equal(tfm['FlaUI.Core']?.resolved, '5.0.0');
assert.equal(tfm['FlaUI.UIA3']?.resolved, '5.0.0');
assert.ok(
  tfm['Microsoft.NET.ILLink.Tasks'],
  'single-file publish dependency must be locked',
);

const gitignore = await fs.readFile(path.join(repoRoot, '.gitignore'), 'utf8');
assert.match(gitignore, /^\*\*\/bin\/$/m, '.NET bin directories must be ignored');
assert.match(gitignore, /^\*\*\/obj\/$/m, '.NET obj directories must be ignored');

const codespellConfig = await fs.readFile(path.join(repoRoot, '.codespellrc'), 'utf8');
const ignoreWordsLine = codespellConfig
  .split(/\r?\n/)
  .find((line) => line.startsWith('ignore-words-list = '));
assert.ok(ignoreWordsLine, 'codespell ignore-word configuration must exist');
const ignoredWords = ignoreWordsLine
  .slice('ignore-words-list = '.length)
  .split(',')
  .map((word) => word.trim())
  .filter(Boolean);
assert.ok(
  ignoredWords.includes('inout'),
  'codespell must ignore the .NET PipeDirection.InOut dictionary entry',
);

const ciWorkflow = await fs.readFile(
  path.join(repoRoot, '.github', 'workflows', 'ci.yml'),
  'utf8',
);
assert.match(ciWorkflow, /^  windows-ui-bridge:$/m);
assert.match(ciWorkflow, /^    runs-on: windows-2025$/m);
assert.ok(
  ciWorkflow.includes(
    'actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0',
  ),
  'Windows UI bridge CI must pin actions/setup-dotnet v6.0.0 by SHA',
);
assert.ok(ciWorkflow.includes('global-json-file: companion/windows-ui/global.json'));
assert.ok(ciWorkflow.includes('dotnet restore .\\DesktopCommander.UiBridge\\DesktopCommander.UiBridge.csproj --locked-mode'));
assert.ok(ciWorkflow.includes('dotnet publish .\\DesktopCommander.UiBridge\\DesktopCommander.UiBridge.csproj -c Release --no-restore'));

const pipeServer = await fs.readFile(
  path.join(projectRoot, 'NamedPipeBridgeServer.cs'),
  'utf8',
);
assert.ok(pipeServer.includes('PipeOptions.CurrentUserOnly'));
assert.ok(pipeServer.includes('"health" =>'));
assert.ok(pipeServer.includes('"snapshot" =>'));
assert.equal(pipeServer.includes('"click" =>'), false);
assert.equal(pipeServer.includes('"type" =>'), false);

console.log('UI bridge source and publish contract: PASS');
