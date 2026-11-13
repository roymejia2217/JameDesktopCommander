# Executed only under a fresh non-administrator profile on an ephemeral GitHub Windows runner.
# Per-user lifecycle assertions remain; the host runner independently checks the
# machine-global firewall at three mandatory, acknowledged checkpoints.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InstallerPath,
  [Parameter(Mandatory)][string]$ExpectedSid,
  [Parameter(Mandatory)][string]$ExpectedCommit,
  [Parameter(Mandatory)][string]$ExpectedVersion,
  [Parameter(Mandatory)][string]$NodeExecutable,
  [Parameter(Mandatory)][string]$FirewallSignalEvent,
  [Parameter(Mandatory)][string]$FirewallResumeEvent
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_PROFILE'
trap {
  # Deliberately disclose only the fixed phase label, not private paths, values or tokens.
  [Console]::Error.WriteLine($script:AcceptancePhase)
  break
}
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
# Start-Process -Credential can inherit the hosting runner's process environment.
# Bind it to the SID-specific, OS-maintained profile and HKCU shell folders.
# Never reuse USERPROFILE/APPDATA/LOCALAPPDATA inherited from runneradmin.
$profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$ExpectedSid"
$profileRecord = Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop
$profileRaw = [Environment]::ExpandEnvironmentVariables([string]$profileRecord.ProfileImagePath)
if (!$profileRaw -or ![IO.Path]::IsPathRooted($profileRaw)) {
  throw 'E_INSTALLER_TEST_USER_PROFILE_OS_SOURCE_INVALID'
}
$profile = [IO.Path]::GetFullPath($profileRaw).TrimEnd('\')
if (!(Test-Path -LiteralPath $profile -PathType Container)) {
  throw 'E_INSTALLER_TEST_USER_PROFILE_NOT_PROVISIONED'
}
$env:USERPROFILE = $profile
$userShellKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
$folders = Get-ItemProperty -LiteralPath $userShellKey -Name 'AppData','Local AppData' -ErrorAction Stop
$roamingRaw = [Environment]::ExpandEnvironmentVariables([string]$folders.AppData)
$localRaw = [Environment]::ExpandEnvironmentVariables([string]$folders.'Local AppData')
if (!$roamingRaw -or !$localRaw -or
    ![IO.Path]::IsPathRooted($roamingRaw) -or ![IO.Path]::IsPathRooted($localRaw)) {
  throw 'E_INSTALLER_TEST_USER_SHELL_FOLDERS_INVALID'
}
$expectedAppData = [IO.Path]::GetFullPath($roamingRaw).TrimEnd('\')
$expectedLocal = [IO.Path]::GetFullPath($localRaw).TrimEnd('\')
if (!$expectedAppData.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase) -or
    !$expectedLocal.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'E_INSTALLER_TEST_USER_PROFILE_ENVIRONMENT_MISMATCH'
}
$env:APPDATA = $expectedAppData
$env:LOCALAPPDATA = $expectedLocal
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
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE'
$startupKeys = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$environmentKeys = @('HKCU:\Environment', 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
# Type- and byte-aware registry evidence; no startup values leave CI logs.
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_REGISTRY_TESTS'
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
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_REGISTRY_STARTUP'
$startupBefore = @{}
foreach ($key in $startupKeys) {
  $startupBefore[$key] = Get-RegistrySnapshotDetail -Key $key
}
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_STARTUP_FILES'
$startupFilesBefore = Get-StartupFilesSnapshot
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_ENVIRONMENT'
$environmentBefore = Get-RegistrySnapshot $environmentKeys
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_FIREWALL'
if ($FirewallSignalEvent -cnotmatch '^Local\\JDC-Installer-[a-f0-9]{32}-Signal$' -or
    $FirewallResumeEvent -cnotmatch '^Local\\JDC-Installer-[a-f0-9]{32}-Resume$') {
  throw 'E_INSTALLER_FIREWALL_SYNC_NAME_INVALID'
}
$firewallSignal = [System.Threading.EventWaitHandleAcl]::OpenExisting(
  $FirewallSignalEvent, [Security.AccessControl.EventWaitHandleRights]::Modify)
$firewallResume = [System.Threading.EventWaitHandleAcl]::OpenExisting(
  $FirewallResumeEvent, [Security.AccessControl.EventWaitHandleRights]::Synchronize)
function Wait-ForHostFirewallObserver {
  if (!$firewallSignal.Set() -or !$firewallResume.WaitOne(180000)) {
    throw 'E_INSTALLER_HOST_FIREWALL_OBSERVER_UNAVAILABLE'
  }
}
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
}
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_TASKS'
$taskNamesBefore = @(Get-ScheduledTask | Where-Object { $_.TaskName -match 'JameDesktop|Desktop Commander' } |
  Sort-Object TaskName | ForEach-Object { $_.TaskName + '|' + $_.Actions[0].Execute })
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_SERVICES'
$servicesBefore = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'JameDesktop|DesktopCommander|JDC' } |
  Sort-Object Name | ForEach-Object { $_.Name + '|' + $_.PathName })
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_BASELINE_SENTINEL'
$profileSentinel = Join-Path $env:LOCALAPPDATA 'OpenAI\tunnel-client\profiles\jdc-ci-uninstall-sentinel.txt'
if (Test-Path $uninstallKey) { throw 'Refusing to overwrite an existing JDC installation' }
if (Test-Path $profileSentinel) { throw 'Refusing to overwrite existing operator profile' }
New-Item -ItemType Directory -Path (Split-Path $profileSentinel) -Force | Out-Null
[IO.File]::WriteAllText($profileSentinel, 'JDC_PREEXISTING_PROFILE_UNTOUCHED')
$profileHash = (Get-FileHash $profileSentinel -Algorithm SHA256).Hash
Wait-ForHostFirewallObserver
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_INSTALL'
$result = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/DIR=`"$target`"") -Wait -PassThru
if ($result.ExitCode -ne 0) { throw "Windows install failed: $($result.ExitCode)" }
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_INSTALLED_ASSERTIONS'
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
Wait-ForHostFirewallObserver
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
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_UNINSTALL'
$result = Start-Process -FilePath $uninstall.FullName -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru
if ($result.ExitCode -ne 0) { throw "Windows uninstall failed: $($result.ExitCode)" }
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_UNINSTALLED_ASSERTIONS'
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
Wait-ForHostFirewallObserver
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
