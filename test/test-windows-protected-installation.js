import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const installer = read('../packaging/windows/JameDesktopCommander.iss');
const workflow = read('../.github/workflows/distribution-candidate.yml');
const runner = read('./security/windows-installer-acceptance-runner.ps1');
const child = read('./security/windows-installer-acceptance.ps1');

test('the protected candidate requires explicit admin installation to a distinct fixed machine root', () => {
  assert.match(installer, /#ifdef JDC_PROTECTED_INSTALL[\s\S]*?PrivilegesRequired=admin/);
  assert.match(installer, /DefaultDirName=\{autopf\}\\JameDesktopCommander Managed Candidate/);
  assert.match(installer, /DisableDirPage=yes/);
  assert.match(installer, /UsePreviousAppDir=no/);
  assert.match(installer, /function PrepareToInstall\(/);
  assert.match(installer, /IsAdminInstallMode/);
  assert.match(installer, /CompareText\(ExpandConstant\('\{app\}'\)/);
  assert.match(installer, /E_PROTECTED_INSTALL_TARGET_EXISTS/);
  assert.match(installer, /PrivilegesRequired=lowest/);
  assert.doesNotMatch(installer, /^\[(Run|Registry|Services)\]/mi);
});

test('the existing CI installer acceptance includes an unprivileged custody gate', () => {
  assert.match(workflow, /\/DJDC_PROTECTED_INSTALL/);
  assert.match(workflow, /-ProtectedInstallerPath/);
  assert.match(runner, /\$ProtectedInstallerPath/);
  assert.match(runner, /-ProtectedInstallRoot/);
  assert.match(runner, /WINDOWS_PROTECTED_INSTALL_CUSTODY=PASS/);
  assert.match(child, /ProtectedInstallRoot/);
  assert.match(child, /FileAccess\]::Write/);
  assert.match(child, /FileMode\]::CreateNew/);
  assert.match(child, /Directory\]::Move/);
  assert.match(child, /--check-installation/);
  assert.match(child, /WINDOWS_PROTECTED_INSTALL_CUSTODY=PASS/);
});

test('failed custody never authorizes an elevated package uninstaller', () => {
  assert.match(runner, /\$custodyVerified = \$false/);
  assert.match(runner, /\$custodyVerified = \$true/);
  assert.match(runner, /if \(\$custodyVerified -and \$null -ne \$uninstallerHash\)/);
  assert.match(runner, /E_PROTECTED_INSTALL_CUSTODY_CLEANUP_UNSAFE/);
});

test('protected acceptance independently probes delete rights and both uninstall inputs', () => {
  assert.match(child, /CreateFileW/);
  assert.match(child, /Assert-ProtectedAccessDenied \$item.FullName \$deleteAccess/);
  assert.match(child, /Assert-ProtectedAccessDenied \$directory \$deleteChildAccess/);
  assert.match(child, /Assert-ProtectedAccessDenied \(Split-Path -Parent \$expectedRoot\) \$deleteChildAccess/);
  assert.match(child, /'unins000\.dat'/);
  assert.match(child, /E_PROTECTED_DELETE_PROBE_CONTROL_FAILED/);
  assert.match(runner, /\$protectedUninstallData = Join-Path \$protectedRoot 'unins000.dat'/);
  assert.match(runner, /\$uninstallDataHash = \(Get-FileHash -LiteralPath \$protectedUninstallData/);
  assert.match(runner, /\(Get-FileHash -LiteralPath \$protectedUninstallData -Algorithm SHA256\).Hash -cne \$uninstallDataHash/);
  assert.match(runner, /\$dataItem.Attributes -band \[IO.FileAttributes\]::ReparsePoint/);
});

test('protected cleanup preserves the primary acceptance failure', () => {
  assert.match(runner, /\$protectedFailure = \$_/);
  assert.match(runner, /if \(\$null -eq \$protectedFailure\) \{ throw \}/);
  assert.match(runner, /\$primaryFailure = \$_/);
  assert.match(runner, /if \(\$null -eq \$primaryFailure\) \{ throw \$cleanupMessage \}/);
});

test('protected custody independently denies narrow content and metadata mutation rights', () => {
  for (const right of ['WriteData','AppendData','WriteExtendedAttributes','WriteAttributes','ChangePermissions','TakeOwnership']) {
    assert.ok(child.includes('FileSystemRights]::' + right) || child.includes("'" + right + "'"), right);
  }
  assert.ok(child.includes('Assert-ProtectedAccessDenied $item.FullName $right'));
  assert.ok(child.includes('E_PROTECTED_WRITE_PROBE_CONTROL_FAILED'));
  assert.ok(child.includes('E_PROTECTED_MUTATION_ACCESS_UNVERIFIED'));
});

test('cleanup checks and calibration cleanup are guarded against secondary failure', () => {
  // Exercise the same structural guard on both supported checkout formats.
  for (const source of [runner.replace(/\r\n/g, "\n"), runner.replace(/\r?\n/g, "\r\n")]) {
    assert.match(source, /try \{\r?\n      if \(Test-Path -LiteralPath \$path -ErrorAction Stop\)/);
  }
  assert.ok(runner.includes("catch { $cleanupFailures.Add('CHILD_DISPOSE') }"));
  assert.ok(child.includes('$calibrationFailure = $_'));
  assert.ok(child.includes('if ($null -eq $calibrationFailure) { throw }'));
});

test('directory custody probes do not silently add SYNCHRONIZE access', () => {
  assert.ok(child.includes('NtOpenFile'));
  assert.ok(child.includes('E_PROTECTED_EXACT_ACCESS_CALIBRATION_FAILED'));
  assert.ok(child.includes('SetKernelObjectSecurity'));
});

test('mutating custody probes preserve failures and only undo confirmed changes', () => {
  assert.ok(child.includes('function Assert-ProtectedMutationDenied'));
  assert.ok(child.includes('$state.Changed'));
  assert.ok(child.includes('E_PROTECTED_MUTATION_CLEANUP_AFTER_PRIMARY_FAILURE'));
  for (const code of ['E_PROTECTED_MUTATION_CLEANUP_AFTER_PRIMARY_FAILURE',
    'E_PROTECTED_CALIBRATION_CLEANUP_AFTER_PRIMARY_FAILURE']) {
    assert.ok(runner.includes(code), code);
  }
});

test('Windows mutation probe preserves the primary error and skips unneeded cleanup', {
  skip: process.platform !== 'win32',
}, () => {
  const start = child.indexOf('  function Assert-AccessDenied(');
  const end = child.indexOf('  # Request individual native mutation rights', start);
  assert.ok(start >= 0 && end > start);
  const exercise = "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n$observed = @{ Undo = 0 }\nAssert-ProtectedMutationDenied {\n  param($state)\n  throw [UnauthorizedAccessException]::new()\n} { $observed.Undo++ } 'E_UNEXPECTED_SUCCESS'\nif ($observed.Undo -ne 0) { throw 'denied operation attempted cleanup' }\ntry {\n  Assert-ProtectedMutationDenied {\n    param($state)\n    $state.Changed = $true\n  } { $observed.Undo++; throw 'SYNTHETIC_CLEANUP_FAILURE' } 'E_PRIMARY_PROBE_FAILURE'\n  throw 'unexpected successful probe'\n} catch {\n  if ($_.Exception.Message -cne 'E_PRIMARY_PROBE_FAILURE') { throw }\n}\nif ($observed.Undo -ne 1) { throw 'cleanup count mismatch' }\nWrite-Output 'MUTATION_CLEANUP_PRIMARY_PRESERVED'";
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    child.slice(start, end) + '\n' + exercise], { encoding: 'utf8', timeout: 12000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /MUTATION_CLEANUP_PRIMARY_PRESERVED/);
  assert.match(result.stderr, /E_PROTECTED_MUTATION_CLEANUP_AFTER_PRIMARY_FAILURE/);
  assert.doesNotMatch(result.stderr, /SYNTHETIC_CLEANUP_FAILURE/);
});
