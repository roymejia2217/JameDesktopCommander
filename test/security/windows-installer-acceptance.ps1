# Executed only under a fresh non-administrator profile on an ephemeral GitHub Windows runner.
# Preserve the original lifecycle and no-host-modification assertions verbatim below.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InstallerPath,
  [Parameter(Mandatory)][string]$ExpectedSid,
  [Parameter(Mandatory)][string]$ExpectedCommit,
  [Parameter(Mandatory)][string]$ExpectedVersion,
  [Parameter(Mandatory)][string]$NodeExecutable
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExpectedSid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$' -or
    $ExpectedCommit -notmatch '^[0-9a-f]{40}$') {
  throw 'E_INSTALLER_EXPECTED_PROVENANCE_INVALID'
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -cne $ExpectedSid -or
    $identity.IsSystem -or $identity.IsGuest -or $identity.IsAnonymous -or
    [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'E_INSTALLER_INCORRECT_TEST_PRINCIPAL'
}
if (!(Test-Path -LiteralPath ("Registry::HKEY_USERS\" + $ExpectedSid))) {
  throw 'E_INSTALLER_TEST_USER_PROFILE_HIVE_NOT_LOADED'
}
$profile = [Environment]::GetFolderPath('UserProfile')
$expectedAppData = [Environment]::GetFolderPath('ApplicationData')
$expectedLocal = [Environment]::GetFolderPath('LocalApplicationData')
if (!$profile -or !$expectedAppData -or !$expectedLocal -or
    $env:APPDATA -ine $expectedAppData -or
    $env:LOCALAPPDATA -ine $expectedLocal -or
    $env:USERPROFILE -ine $profile -or
    !$expectedLocal.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'E_INSTALLER_TEST_USER_PROFILE_ENVIRONMENT_MISMATCH'
}
if (!(Test-Path -LiteralPath $InstallerPath -PathType Leaf) -or
    !(Test-Path -LiteralPath $NodeExecutable -PathType Leaf)) {
  throw 'E_INSTALLER_VERIFIED_INPUT_UNAVAILABLE'
}
Set-Alias -Name node -Value $NodeExecutable -Scope Script
$env:JDC_CANDIDATE_SOURCE_SHA = $ExpectedCommit
$version = $ExpectedVersion
$setup = $InstallerPath
$target = Join-Path $env:LOCALAPPDATA 'JDC-isolated-installer-acceptance'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{C812A487-AF99-4640-9F77-31DD4A9A7F12}_is1'
$launcher = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\JameDesktopCommander (MCP console).lnk'
$operatorShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\JameDesktopCommander - Tunnel Operator.lnk'
# Installation must not add autoruns, environment entries or firewall exceptions.
# Observe complete native registry/firewall state, but never print their values.
$startupKeys = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$environmentKeys = @('HKCU:\Environment', 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
# Type- and byte-aware registry evidence; no startup values leave CI logs.
. (Join-Path $PWD 'scripts/windows-registry-snapshot.ps1')
& (Join-Path $PWD 'test/security/test-windows-installer-registry-snapshot.ps1')
& (Join-Path $PWD 'test/security/test-windows-installer-registry-drift-evidence.ps1')
function Get-StartupFilesSnapshot {
  $locations = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
  )
  $entries = foreach ($location in $locations) {
    if (!(Test-Path -LiteralPath $location)) { "$location|absent"; continue }
    Get-ChildItem -LiteralPath $location -File -Recurse |
      Sort-Object FullName | ForEach-Object {
        $_.FullName + '|' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
      }
  }
  return ($entries -join [char]10)
}
function Get-FirewallSnapshot {
  $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object Name | ForEach-Object {
      $_.Name + '|' + $_.DisplayName + '|' + $_.Enabled + '|' + $_.Direction + '|' + $_.Action
    })
  $ports = @(Get-NetFirewallPortFilter -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object InstanceID | ForEach-Object {
      $_.InstanceID + '|' + $_.Protocol + '|' + ($_.LocalPort -join ',') + '|' + ($_.RemotePort -join ',')
    })
  $applications = @(Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object InstanceID | ForEach-Object { $_.InstanceID + '|' + $_.Program })
  return ((@($rules) + @($ports) + @($applications)) -join [char]10)
}
$startupBefore = @{}
foreach ($key in $startupKeys) {
  $startupBefore[$key] = Get-RegistrySnapshotDetail -Key $key
}
$startupFilesBefore = Get-StartupFilesSnapshot
$environmentBefore = Get-RegistrySnapshot $environmentKeys
$firewallBefore = Get-FirewallSnapshot
function Assert-HostPackageBoundary {
  $changedStartupKeys = @(
    foreach ($key in $startupKeys) {
      $after = Get-RegistrySnapshotDetail -Key $key
      if ($after.Snapshot -cne $startupBefore[$key].Snapshot) {
        $counts = Get-RegistryChangeSummary -Before $startupBefore[$key] -After $after
        "$key ($counts)"
      }
    }
  )
  if ($changedStartupKeys.Count -ne 0) {
    # Only names of fixed, known registry keys; never emit registry values.
    throw ('Windows startup registry drift during installer acceptance (cause unverified): ' +
      ($changedStartupKeys -join ', '))
  }
  if ((Get-StartupFilesSnapshot) -cne $startupFilesBefore) {
    throw 'Pre-existing Windows startup folder files modified by installer'
  }
  if ((Get-RegistrySnapshot $environmentKeys) -cne $environmentBefore) {
    throw 'Windows environment registration modified by installer'
  }
  if ((Get-FirewallSnapshot) -cne $firewallBefore) {
    throw 'Windows firewall rules modified by installer'
  }
}
$taskNamesBefore = @(Get-ScheduledTask | Where-Object { $_.TaskName -match 'JameDesktop|Desktop Commander' } |
  Sort-Object TaskName | ForEach-Object { $_.TaskName + '|' + $_.Actions[0].Execute })
$servicesBefore = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'JameDesktop|DesktopCommander|JDC' } |
  Sort-Object Name | ForEach-Object { $_.Name + '|' + $_.PathName })
$profileSentinel = Join-Path $env:LOCALAPPDATA 'OpenAI\tunnel-client\profiles\jdc-ci-uninstall-sentinel.txt'
if (Test-Path $uninstallKey) { throw 'Refusing to overwrite an existing JDC installation' }
if (Test-Path $profileSentinel) { throw 'Refusing to overwrite existing operator profile' }
New-Item -ItemType Directory -Path (Split-Path $profileSentinel) -Force | Out-Null
[IO.File]::WriteAllText($profileSentinel, 'JDC_PREEXISTING_PROFILE_UNTOUCHED')
$profileHash = (Get-FileHash $profileSentinel -Algorithm SHA256).Hash
$result = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/DIR=`"$target`"") -Wait -PassThru
if ($result.ExitCode -ne 0) { throw "Windows install failed: $($result.ExitCode)" }
if (!(Test-Path $uninstallKey)) { throw 'Installed JDC uninstall registration missing' }
$registered = Get-ItemProperty $uninstallKey
if ($registered.DisplayName -ne 'JameDesktopCommander' -or $registered.DisplayVersion -ne $version) {
  throw 'Windows uninstall registration identity/version mismatch'
}
if ([IO.Path]::GetFullPath($registered.InstallLocation).TrimEnd('\') -ine [IO.Path]::GetFullPath($target).TrimEnd('\')) {
  throw 'Windows uninstall registration targets wrong directory'
}
if (!(Test-Path $launcher) -or !(Test-Path $operatorShortcut)) {
  throw 'Installed Windows launcher shortcuts missing'
}
$tasksAfterInstall = @(Get-ScheduledTask | Where-Object { $_.TaskName -match 'JameDesktop|Desktop Commander' } |
  Sort-Object TaskName | ForEach-Object { $_.TaskName + '|' + $_.Actions[0].Execute })
if (($tasksAfterInstall -join '|') -ne ($taskNamesBefore -join '|')) {
  throw 'Unexpected JDC Scheduled Task added by installer'
}
$servicesAfterInstall = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'JameDesktop|DesktopCommander|JDC' } |
  Sort-Object Name | ForEach-Object { $_.Name + '|' + $_.PathName })
if (($servicesAfterInstall -join '|') -ne ($servicesBefore -join '|')) {
  throw 'Unexpected JDC service added by per-user installer'
}
if ((Get-FileHash $profileSentinel -Algorithm SHA256).Hash -ne $profileHash) {
  throw 'Pre-existing tunnel profile modified by installer'
}
Assert-HostPackageBoundary
$runtime = Join-Path $target 'runtime/node.exe'
if (!(Test-Path -LiteralPath $runtime)) { throw 'Installed runtime missing' }
& $runtime --version
if ($LASTEXITCODE -ne 0) { throw 'Installed Node execution failed' }
if (!(Test-Path (Join-Path $target 'dist/index.js'))) { throw 'Installed MCP entrypoint missing' }
$tunnel = Join-Path $target 'tools/tunnel-client/tunnel-client.exe'
if (!(Test-Path -LiteralPath $tunnel)) { throw 'Installed tunnel client missing' }
$tunnelVersion = & $tunnel --version
if ($LASTEXITCODE -ne 0 -or $tunnelVersion -notmatch '^0\.0\.19') { throw 'Installed tunnel client version mismatch' }
$gui = Join-Path $target 'jdc-tunnel-operator-ui.exe'
$uiManifest = Join-Path $target 'operator-ui-manifest.json'
if (!(Test-Path -LiteralPath $gui -PathType Leaf) -or !(Test-Path -LiteralPath $uiManifest -PathType Leaf)) { throw 'Installed GUI or source manifest missing' }
node scripts/operator-ui-bundle.mjs verify-installed $target $env:JDC_CANDIDATE_SOURCE_SHA
if ($LASTEXITCODE -ne 0) { throw 'Installed GUI or font notices differ from source candidate' }
$uiCheck = Start-Process -FilePath $gui -ArgumentList '--check-installation' -WorkingDirectory $target -Wait -PassThru
if ($uiCheck.ExitCode -ne 0) { throw "Native operator read-only contract rejected: $($uiCheck.ExitCode)" }
$uninstall = Get-ChildItem -LiteralPath $target -Filter 'unins*.exe' -File | Select-Object -First 1
if (!$uninstall) { throw 'Expected Inno uninstall executable missing' }
$result = Start-Process -FilePath $uninstall.FullName -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru
if ($result.ExitCode -ne 0) { throw "Windows uninstall failed: $($result.ExitCode)" }
if (Test-Path $uninstallKey) { throw 'JDC uninstall registration remains after uninstall' }
if (Test-Path $launcher) { throw 'Windows launcher shortcut remains after uninstall' }
if (Test-Path $operatorShortcut) { throw 'Windows operator shortcut remains after uninstall' }
if (Test-Path $runtime) { throw 'Installed Node runtime remains after uninstall' }
if (Test-Path $tunnel) { throw 'Bundled tunnel client remains after uninstall' }
if (Test-Path (Join-Path $target 'dist/index.js')) { throw 'MCP entrypoint remains after uninstall' }
if (Test-Path -LiteralPath $target) { throw 'Installer directory remains after uninstall' }
$tasksAfterUninstall = @(Get-ScheduledTask | Where-Object { $_.TaskName -match 'JameDesktop|Desktop Commander' } |
  Sort-Object TaskName | ForEach-Object { $_.TaskName + '|' + $_.Actions[0].Execute })
if (($tasksAfterUninstall -join '|') -ne ($taskNamesBefore -join '|')) {
  throw 'Pre-existing JDC Scheduled Task modified by uninstaller'
}
$servicesAfterUninstall = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'JameDesktop|DesktopCommander|JDC' } |
  Sort-Object Name | ForEach-Object { $_.Name + '|' + $_.PathName })
if (($servicesAfterUninstall -join '|') -ne ($servicesBefore -join '|')) {
  throw 'Pre-existing JDC Windows service modified by uninstaller'
}
if ((Get-FileHash $profileSentinel -Algorithm SHA256).Hash -ne $profileHash) {
  throw 'Pre-existing tunnel profile modified by uninstaller'
}
Assert-HostPackageBoundary
$ownedProcesses = @(Get-CimInstance Win32_Process | Where-Object {
  $_.ExecutablePath -and $_.ExecutablePath.StartsWith(
    ($target + [IO.Path]::DirectorySeparatorChar),
    [StringComparison]::OrdinalIgnoreCase)
})
if ($ownedProcesses.Count -ne 0) { throw 'JDC process remains after uninstall' }
Remove-Item -LiteralPath $profileSentinel -Force
if (Test-Path -LiteralPath $gui) { throw 'GUI remains after uninstall' }
if (Test-Path -LiteralPath $uiManifest) { throw 'GUI manifest remains after uninstall' }
if (Test-Path -LiteralPath (Join-Path $target 'licenses/operator-ui')) { throw 'Native UI license notices remain after uninstall' }

Write-Output 'WINDOWS_ISOLATED_PRINCIPAL_INSTALL_UNINSTALL=PASS'
