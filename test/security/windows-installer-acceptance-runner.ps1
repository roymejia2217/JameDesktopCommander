# Disposable GitHub-hosted Windows installer acceptance with an isolated HKCU.
# Uses supported Windows LocalAccounts and Start-Process -Credential APIs.
# Not a product installer or a script to run on an installed workstation.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InstallerPath,
  [Parameter(Mandatory)][string]$SourceCommit,
  [Parameter(Mandatory)][string]$Version
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:GITHUB_REPOSITORY -cne 'roymejia2217/JameDesktopCommander') {
  throw 'E_INSTALLER_EPHEMERAL_WINDOWS_RUNNER_REQUIRED'
}
if ($SourceCommit -notmatch '^[0-9a-f]{40}$' -or $Version -notmatch '^\d+\.\d+\.\d+$' -or
    !(Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
  throw 'E_INSTALLER_UNVERIFIED_SOURCE'
}
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
$node = (Get-Command node.exe -ErrorAction Stop).Source
$pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$runId = [guid]::NewGuid().ToString('N')
$accountName = 'jdcinst-' + $runId.Substring(0,8)
$stage = Join-Path $env:ProgramData ('JDC-Isolated-Installer-' + $runId)
$stdout = Join-Path $env:RUNNER_TEMP ('JDC-' + $runId + '.out')
$stderr = Join-Path $env:RUNNER_TEMP ('JDC-' + $runId + '.err')
$createdAccount = $null
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
$installerHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
try {
  if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) {
    throw 'E_INSTALLER_EXISTING_TEST_ACCOUNT'
  }
  if (Test-Path -LiteralPath $stage) { throw 'E_INSTALLER_TEST_STAGE_EXISTS' }
  $password = 'Aa1!' + [Convert]::ToBase64String(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  $createdAccount = New-LocalUser -Name $accountName -Password $securePassword `
    -PasswordNeverExpires -UserMayNotChangePassword -Description 'Disposable JDC installer CI'
  $credential = [pscredential]::new("$env:COMPUTERNAME\$accountName", $securePassword)
  $sid = $createdAccount.SID
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  if ($sid.Value -eq 'S-1-5-18' -or
      (@(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop).SID.Value) -contains $sid.Value) {
    throw 'E_INSTALLER_TEST_USER_IS_ADMINISTRATOR'
  }
  New-Item -Path $stage -ItemType Directory -ErrorAction Stop | Out-Null
  $acl = Get-Acl -LiteralPath $stage
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($trustee in @($acl.Access | ForEach-Object { $_.IdentityReference } |
      Select-Object -Unique)) { $acl.PurgeAccessRules($trustee) }
  $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach ($grant in @(
    @{Sid=$adminSid; Rights='FullControl'},
    @{Sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-18'); Rights='FullControl'},
    @{Sid=$sid; Rights='ReadAndExecute'}
  )) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
      $grant.Sid, [Enum]::Parse([Security.AccessControl.FileSystemRights], $grant.Rights),
      $inherit, [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow)
    $acl.SetAccessRule($rule)
  }
  Set-Acl -LiteralPath $stage -AclObject $acl -ErrorAction Stop
  if (!(Get-Acl -LiteralPath $stage).AreAccessRulesProtected) {
    throw 'E_INSTALLER_TEST_STAGE_ACL_UNPROTECTED'
  }
  foreach ($relative in @(
    'scripts/windows-registry-snapshot.ps1',
    'scripts/operator-ui-bundle.mjs',
    'test/security/windows-installer-acceptance.ps1',
    'test/security/test-windows-installer-registry-snapshot.ps1',
    'test/security/test-windows-installer-registry-drift-evidence.ps1'
  )) {
    $source = Join-Path $sourceRoot $relative
    $destination = Join-Path $stage $relative
    New-Item -Path (Split-Path $destination) -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) {
      throw 'E_INSTALLER_TEST_STAGED_SOURCE_CHANGED'
    }
  }
  $setup = Join-Path $stage 'UNPUBLISHED-jdc-installer-win32-x64.exe'
  Copy-Item -LiteralPath $InstallerPath -Destination $setup -ErrorAction Stop
  if ((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -cne $installerHash) {
    throw 'E_INSTALLER_STAGED_BINARY_HASH_MISMATCH'
  }
  $arguments = @(
    '-NoProfile', '-NonInteractive', '-File',
    (Join-Path $stage 'test/security/windows-installer-acceptance.ps1'),
    '-InstallerPath', $setup,
    '-ExpectedSid', $sid.Value,
    '-ExpectedCommit', $SourceCommit,
    '-ExpectedVersion', $Version,
    '-NodeExecutable', ('"' + $node + '"')
  )
  $child = Start-Process -FilePath $pwsh -Credential $credential -LoadUserProfile `
    -ArgumentList $arguments -WorkingDirectory $stage -Wait -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
  if ($null -eq $child.ExitCode -or $child.ExitCode -ne 0) {
    # Never relay untrusted child stdout/stderr or expose registry value names.
    # The child emits exactly one bounded stage code before failing closed.
    $diagnostics = @(Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue)
    $phase = @($diagnostics | Where-Object {
      $_ -cmatch '^E_INSTALLER_ACCEPTANCE_PHASE_(PROFILE|BASELINE|INSTALL|INSTALLED_ASSERTIONS|UNINSTALL|UNINSTALLED_ASSERTIONS)$'
    } | Select-Object -Last 1)
    if ($phase.Count -eq 1) {
      Write-Output $phase[0]
    } else {
      Write-Output 'E_INSTALLER_ACCEPTANCE_PHASE_UNOBSERVED'
    }
    $privateEvidence = $diagnostics -join [char]10
    if ($privateEvidence.Contains('Windows startup registry drift during installer acceptance')) {
      Write-Output 'E_INSTALLER_STARTUP_REGISTRY_DRIFT'
      foreach ($summary in [regex]::Matches($privateEvidence,
        'presenceChanged=(?:true|false);added=[0-9]+;removed=[0-9]+;typeChanged=[0-9]+;dataChanged=[0-9]+')) {
        Write-Output $summary.Value
      }
    }
    throw "E_INSTALLER_ISOLATED_CHILD_FAILED_EXIT_$($child.ExitCode)"
  }
  $output = Get-Content -LiteralPath $stdout -Raw -ErrorAction Stop
  if ($output -notmatch 'WINDOWS_ISOLATED_PRINCIPAL_INSTALL_UNINSTALL=PASS') {
    throw 'E_INSTALLER_CHILD_SUCCESS_WITNESS_MISSING'
  }
  Write-Output 'WINDOWS_ISOLATED_PRINCIPAL_ACCEPTANCE=PASS'
 } finally {
  # The runner is disposable, but CI still verifies complete owned cleanup.
  if ($null -ne $createdAccount) {
    try {
      $profile = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop |
        Where-Object { $_.SID -ceq $createdAccount.SID.Value })
      foreach ($entry in $profile) {
        Remove-CimInstance -InputObject $entry -ErrorAction Stop
      }
    } catch { $cleanupFailures.Add('USER_PROFILE') }
    try { Remove-LocalUser -Name $accountName -ErrorAction Stop }
    catch { $cleanupFailures.Add('LOCAL_USER') }
  }
  foreach ($path in @($stage, $stdout, $stderr)) {
    if (Test-Path -LiteralPath $path) {
      try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop }
      catch { $cleanupFailures.Add('OWNED_FILES') }
    }
  }
  if ($cleanupFailures.Count -ne 0) {
    throw ('E_INSTALLER_ISOLATED_TEST_CLEANUP_FAILED_' +
      ($cleanupFailures -join '_'))
  }
}
