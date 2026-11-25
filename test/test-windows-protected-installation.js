import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

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
