import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import YAML from 'yaml';

const workflow = YAML.parse(readFileSync(
  new URL('../.github/workflows/distribution-candidate.yml', import.meta.url), 'utf8'));
const run = workflow.jobs['portable-candidate'].steps.find(
  (step) => step.name === 'Verify Windows installer install and uninstall').run;
assert.match(run, /windows-installer-acceptance-runner[.]ps1/);
const acceptance = readFileSync(
  new URL('./security/windows-installer-acceptance.ps1', import.meta.url), 'utf8');
const gate = acceptance.match(/^function Assert-HostPackageBoundary \{[\s\S]*?^\}/m)?.[0];
const baseline = acceptance.match(/^\$startupBefore[\s\S]*?(?=^\$environmentBefore)/m)?.[0];
assert.ok(gate && baseline, 'Windows installer boundary must be present');

function invokeFixture(kind) {
  const setup = [
    "$script:reg = @{ 'HKCU:\\Run' = 'original'; 'HKLM:\\RunOnce' = 'original' }",
    "$script:files = 'original'",
    'function Get-RegistrySnapshot([string[]]$keys) {',
    '  return (($keys | ForEach-Object { $script:reg[$_] }) -join [char]10)',
    '}',
    // Match the new typed, in-memory evidence contract used by the real gate.
    'function Get-RegistrySnapshotDetail([string]$Key) {',
    '  return [pscustomobject]@{ Snapshot = $script:reg[$Key]; Present = $true; Entries = @{} }',
    '}',
    'function Get-RegistryChangeSummary {',
    '  param([object]$Before, [object]$After)',
    "  return 'presenceChanged=false;added=0;removed=0;typeChanged=0;dataChanged=1'",
    '}',
    'function Get-StartupFilesSnapshot { return $script:files }',
    "$startupKeys = @('HKCU:\\Run', 'HKLM:\\RunOnce')",
    "$environmentKeys = @('HKCU:\\Environment')",
  ];
  const mutation = kind === 'registry'
    ? "$script:reg['HKLM:\\RunOnce'] = 'SECRET_CANARY'"
    : kind === 'startup-files'
      ? "$script:files = 'SECRET_CANARY'"
      : '';
  const script = [
    ...setup, baseline,
    '$environmentBefore = Get-RegistrySnapshot $environmentKeys',
    gate, mutation, 'Assert-HostPackageBoundary',
  ].join('\n');
  return spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command', script,
  ], { encoding: 'utf8', timeout: 12000 });
}

test('installer startup guard identifies the changed registry key without exposing its value', {
  skip: process.platform !== 'win32',
}, () => {
  const result = invokeFixture('registry');
  assert.equal(result.status, 1, result.error?.message);
  assert.match(result.stderr, /HKLM:\\RunOnce/);
  assert.doesNotMatch(result.stderr, /SECRET_CANARY/);
});

test('installer startup guard distinguishes Startup folder drift and preserves failure', {
  skip: process.platform !== 'win32',
}, () => {
  const result = invokeFixture('startup-files');
  assert.equal(result.status, 1, result.error?.message);
  assert.match(result.stderr, /startup folder files modified/i);
  assert.doesNotMatch(result.stderr, /SECRET_CANARY/);
});

test('installer startup guard accepts unchanged snapshots', {
  skip: process.platform !== 'win32',
}, () => {
  const result = invokeFixture('unchanged');
  assert.equal(result.status, 0, result.stderr);
});

const firewall = readFileSync(
  new URL('./security/windows-installer-firewall-snapshot.ps1', import.meta.url), 'utf8');

test('privileged firewall observer rejects a modified post-install snapshot', {
  skip: process.platform !== 'win32',
}, () => {
  const cmd = [firewall, "Assert-HostFirewallSnapshotUnchanged -Before 'safe' -Current 'modified' -Phase INSTALLED"].join('\n');
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
    { encoding: 'utf8', timeout: 12000 });
  assert.equal(result.status, 1, result.error?.message);
  assert.match(result.stderr, /E_INSTALLER_FIREWALL_DRIFT_INSTALLED/);
});

test('privileged firewall observer rejects a modified post-uninstall snapshot', {
  skip: process.platform !== 'win32',
}, () => {
  const cmd = [firewall, "Assert-HostFirewallSnapshotUnchanged -Before 'safe' -Current 'modified' -Phase UNINSTALLED"].join('\n');
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
    { encoding: 'utf8', timeout: 12000 });
  assert.equal(result.status, 1, result.error?.message);
  assert.match(result.stderr, /E_INSTALLER_FIREWALL_DRIFT_UNINSTALLED/);
});

test('privileged firewall observer accepts an unchanged snapshot', {
  skip: process.platform !== 'win32',
}, () => {
  const cmd = [firewall, "Assert-HostFirewallSnapshotUnchanged -Before 'safe' -Current 'safe' -Phase INSTALLED"].join('\n');
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
    { encoding: 'utf8', timeout: 12000 });
  assert.equal(result.status, 0, result.stderr);
});
