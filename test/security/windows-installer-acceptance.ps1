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
  [Parameter(Mandatory)][string]$FirewallResumeEvent,
  [string]$ProtectedInstallRoot = ''
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
# An alternate-credential process may inherit TEMP/TMP from the runner admin.
# Inno Setup requires a writable temporary directory under the actual user.
function Set-VerifiedProfileTemporaryDirectory {
  param(
    [Parameter(Mandatory)][string]$Profile,
    [Parameter(Mandatory)][string]$LocalAppData
  )
  $root = [IO.Path]::GetFullPath($Profile).TrimEnd('\')
  $local = [IO.Path]::GetFullPath($LocalAppData).TrimEnd('\')
  if (!$local.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'E_INSTALLER_USER_TEMP_PROFILE_BOUNDARY_INVALID'
  }
  $temp = [IO.Path]::GetFullPath((Join-Path $local 'Temp')).TrimEnd('\')
  New-Item -ItemType Directory -Path $temp -Force -ErrorAction Stop | Out-Null
  $item = Get-Item -LiteralPath $temp -Force -ErrorAction Stop
  if (!$item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'E_INSTALLER_USER_TEMP_NOT_OWNED_DIRECTORY'
  }
  $probe = Join-Path $temp ('jdc-ci-' + [guid]::NewGuid().ToString('N'))
  try {
    $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
  } finally {
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
  }
  $env:TEMP = $temp
  $env:TMP = $temp
}
Set-VerifiedProfileTemporaryDirectory -Profile $profile -LocalAppData $expectedLocal
if (!(Test-Path -LiteralPath $InstallerPath -PathType Leaf) -or
    !(Test-Path -LiteralPath $NodeExecutable -PathType Leaf)) {
  throw 'E_INSTALLER_VERIFIED_INPUT_UNAVAILABLE'
}
Set-Alias -Name node -Value $NodeExecutable -Scope Script
$env:JDC_CANDIDATE_SOURCE_SHA = $ExpectedCommit
$version = $ExpectedVersion
if ($ProtectedInstallRoot) {
  # The host supplies only the fixed machine-wide candidate root. The caller
  # has already been bound to a real, separate non-administrator token.
  $script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_INSTALLED_ASSERTIONS'
  $expectedRoot = Join-Path ([Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)) 'JameDesktopCommander Managed Candidate'
  if ($ProtectedInstallRoot -ine $expectedRoot -or
      !(Test-Path -LiteralPath $expectedRoot -PathType Container)) {
    throw 'E_PROTECTED_INSTALL_ROOT_INVALID'
  }
  function Assert-AccessDenied([scriptblock]$Attempt, [string]$Code) {
    try { & $Attempt }
    catch {
      $cause = $_.Exception
      while ($null -ne $cause) {
        if ($cause -is [UnauthorizedAccessException] -or
            $cause.HResult -eq -2147024891) { return }
        $cause = $cause.InnerException
      }
      throw
    }
    throw $Code
  }
  function Assert-ProtectedMutationDenied([scriptblock]$Mutation, [scriptblock]$Undo, [string]$Code) {
    $state = @{ Changed = $false }
    $failure = $null
    try {
      Assert-AccessDenied { & $Mutation $state } $Code
      if ($state.Changed) { throw $Code }
    } catch {
      $failure = $_
      throw
    } finally {
      if ($state.Changed) {
        try { & $Undo }
        catch {
          if ($null -eq $failure) { throw }
          [Console]::Error.WriteLine('E_PROTECTED_MUTATION_CLEANUP_AFTER_PRIMARY_FAILURE')
        }
      }
    }
  }
  # Request individual native mutation rights without altering any object.
  # Only ERROR_ACCESS_DENIED proves a negative access result.
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class JdcInstallerAccessProbe {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock {
        public IntPtr Status, Information;
    }
    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtOpenFile(out SafeFileHandle handle, uint desiredAccess,
        ref ObjectAttributes attributes, out IoStatusBlock ioStatus, uint shareAccess, uint openOptions);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[] descriptor);

    public static int OpenExisting(string path, uint access) {
        // The fixture uses only local drive-qualified filesystem paths.
        // NtOpenFile without FILE_SYNCHRONOUS_IO_* requests exactly access.
        // CreateFileW adds rights even in overlapped mode; that is not proof.
        if (path.Length < 3 || path[1] != ':' || path[2] != '\\' ||
            path.IndexOf('\0') >= 0 || path.Length > 32000) return -1;
        string nativePath = @"\??\" + path;
        IntPtr nameBuffer = IntPtr.Zero, namePointer = IntPtr.Zero;
        SafeFileHandle handle = null;
        try {
            nameBuffer = Marshal.StringToHGlobalUni(nativePath);
            var name = new UnicodeString {
                Length = checked((ushort)(nativePath.Length * 2)),
                MaximumLength = checked((ushort)((nativePath.Length + 1) * 2)),
                Buffer = nameBuffer
            };
            namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
            Marshal.StructureToPtr(name, namePointer, false);
            var attributes = new ObjectAttributes {
                Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)),
                ObjectName = namePointer, Attributes = 0x40 // OBJ_CASE_INSENSITIVE
            };
            IoStatusBlock io;
            // Share all; existing object only; do not follow a final reparse point.
            int status = NtOpenFile(out handle, access, ref attributes, out io, 7, 0x00200000);
            if (status == 0 && handle != null && !handle.IsInvalid) return 0;
            return status == unchecked((int)0xC0000022) ? 5 : -1;
        } finally {
            if (handle != null) handle.Dispose();
            if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
        }
    }

    // Retain an ACL restoration handle before denying SYNCHRONIZE on the
    // disposable calibration directory. Never use this on the install root.
    public static SafeFileHandle OpenCalibrationAcl(string path) {
        SafeFileHandle handle = CreateFileW(path, 0x00040000, 7, IntPtr.Zero, 3,
            0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new System.ComponentModel.Win32Exception(error);
        }
        return handle;
    }
    public static void SetCalibrationDacl(SafeFileHandle handle, byte[] descriptor) {
        if (!SetKernelObjectSecurity(handle, 4, descriptor))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
  $deleteAccess = [uint32][Security.AccessControl.FileSystemRights]::Delete
  $deleteChildAccess = [uint32][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
  # Each request is separate: aggregate GENERIC_WRITE denial is not evidence
  # that FILE_WRITE_DATA, FILE_APPEND_DATA or ACL changes are denied.
  $mutationRights = @(
    [uint32][Security.AccessControl.FileSystemRights]::WriteData
    [uint32][Security.AccessControl.FileSystemRights]::AppendData
    [uint32][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    [uint32][Security.AccessControl.FileSystemRights]::WriteAttributes
    [uint32][Security.AccessControl.FileSystemRights]::ChangePermissions
    [uint32][Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  function Assert-ProtectedAccessDenied([string]$Path, [uint32]$Access) {
    $result = [JdcInstallerAccessProbe]::OpenExisting($Path, $Access)
    if ($result -eq 0) { throw 'E_PROTECTED_MUTATION_ACCESS_ALLOWED' }
    if ($result -ne 5) { throw 'E_PROTECTED_MUTATION_ACCESS_UNVERIFIED' }
  }
  # Calibrate on a child-owned disposable directory, including DELETE
  # granted on an existing file while creation of another file is denied.
  $control = Join-Path $env:TEMP ('jdc-delete-control-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $control -ErrorAction Stop | Out-Null
  $originalAcl = $null
  $calibrationFailure = $null
  try {
    $originalAcl = Get-Acl -LiteralPath $control
    $controlFile = Join-Path $control 'existing.txt'
    [IO.File]::WriteAllText($controlFile, 'synthetic')
    $controlAcl = Get-Acl -LiteralPath $control
    $controlAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      $identity.User, [Security.AccessControl.FileSystemRights]::CreateFiles,
      [Security.AccessControl.AccessControlType]::Deny))
    Set-Acl -LiteralPath $control -AclObject $controlAcl
    Assert-AccessDenied {
      $handle = [IO.File]::Open((Join-Path $control 'new.txt'), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
      $handle.Dispose()
    } 'E_PROTECTED_DELETE_PROBE_CONTROL_FAILED'
    if ([JdcInstallerAccessProbe]::OpenExisting($controlFile, $deleteAccess) -ne 0 -or
        [JdcInstallerAccessProbe]::OpenExisting($control, $deleteAccess) -ne 0 -or
        [JdcInstallerAccessProbe]::OpenExisting($control, $deleteChildAccess) -ne 0) {
      throw 'E_PROTECTED_DELETE_PROBE_CONTROL_FAILED'
    }
    # Deny only APPEND_DATA, while WRITE_DATA remains available. This is the
    # adversarial case that a generic write-only check would falsely accept.
    $fileAcl = Get-Acl -LiteralPath $controlFile
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      $identity.User, [Security.AccessControl.FileSystemRights]::AppendData,
      [Security.AccessControl.AccessControlType]::Deny))
    Set-Acl -LiteralPath $controlFile -AclObject $fileAcl
    $genericWrite = [uint32]0x40000000 # Win32 GENERIC_WRITE
    if ([JdcInstallerAccessProbe]::OpenExisting($controlFile, $genericWrite) -ne 5 -or
        [JdcInstallerAccessProbe]::OpenExisting($controlFile, [uint32][Security.AccessControl.FileSystemRights]::WriteData) -ne 0 -or
        [JdcInstallerAccessProbe]::OpenExisting($controlFile, [uint32][Security.AccessControl.FileSystemRights]::AppendData) -ne 5) {
      throw 'E_PROTECTED_WRITE_PROBE_CONTROL_FAILED'
    }
    # A directory with WRITE_DAC but without SYNCHRONIZE is a positive
    # control for exact native access. Retain a handle to restore its ACL.
    $exactDirectory = Join-Path $control 'exact-directory'
    New-Item -ItemType Directory -Path $exactDirectory -ErrorAction Stop | Out-Null
    $originalDescriptor = (Get-Acl -LiteralPath $exactDirectory).GetSecurityDescriptorBinaryForm()
    $aclHandle = [JdcInstallerAccessProbe]::OpenCalibrationAcl($exactDirectory)
    $exactFailure = $null
    try {
      $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($originalDescriptor, 0)
      $synchronize = [uint32][Security.AccessControl.FileSystemRights]::Synchronize
      $denySync = [Security.AccessControl.CommonAce]::new(
        [Security.AccessControl.AceFlags]::None,
        [Security.AccessControl.AceQualifier]::AccessDenied, [int]$synchronize,
        $identity.User, $false, $null)
      $descriptor.DiscretionaryAcl.InsertAce(0, $denySync)
      $descriptorBytes = [byte[]]::new($descriptor.BinaryLength)
      $descriptor.GetBinaryForm($descriptorBytes, 0)
      [JdcInstallerAccessProbe]::SetCalibrationDacl($aclHandle, $descriptorBytes)
      $writeDac = [uint32][Security.AccessControl.FileSystemRights]::ChangePermissions
      if ([JdcInstallerAccessProbe]::OpenExisting($exactDirectory, $synchronize) -ne 5 -or
          [JdcInstallerAccessProbe]::OpenExisting($exactDirectory, $writeDac) -ne 0) {
        throw 'E_PROTECTED_EXACT_ACCESS_CALIBRATION_FAILED'
      }
    } catch {
      $exactFailure = $_
      throw
    } finally {
      try {
        [JdcInstallerAccessProbe]::SetCalibrationDacl($aclHandle, $originalDescriptor)
      } catch {
        if ($null -eq $exactFailure) { throw }
        [Console]::Error.WriteLine('E_PROTECTED_CALIBRATION_CLEANUP_AFTER_PRIMARY_FAILURE')
      } finally { $aclHandle.Dispose() }
    }
  } catch {
    $calibrationFailure = $_
    throw
  } finally {
    try {
      if ($null -ne $originalAcl) {
        Set-Acl -LiteralPath $control -AclObject $originalAcl
      }
      Remove-Item -LiteralPath $control -Recurse -Force -ErrorAction Stop
    } catch {
      if ($null -eq $calibrationFailure) { throw }
      [Console]::Error.WriteLine('E_PROTECTED_CALIBRATION_CLEANUP_AFTER_PRIMARY_FAILURE')
    }
  }
  foreach ($relative in @('runtime','dist','tools','tools\tunnel-client',
      'runtime\node.exe','dist\index.js','jdc-tunnel-operator-ui.exe',
      'tools\tunnel-client\tunnel-client.exe','operator-ui-manifest.json','unins000.exe','unins000.dat')) {
    $item = Get-Item -LiteralPath (Join-Path $expectedRoot $relative) -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'E_PROTECTED_INSTALL_REPARSE_COMPONENT'
    }
    Assert-ProtectedAccessDenied $item.FullName $deleteAccess
    foreach ($right in $mutationRights) {
      Assert-ProtectedAccessDenied $item.FullName $right
    }
    if (!$item.PSIsContainer) {
      # Require an actual readable object and then reject a write handle.
      $null = Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
      Assert-AccessDenied {
        $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open,
          [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $stream.Dispose()
      } 'E_PROTECTED_INSTALL_WRITE_ALLOWED'
    }
  }
  Assert-ProtectedAccessDenied (Split-Path -Parent $expectedRoot) $deleteChildAccess
  foreach ($relative in @('','runtime','dist','tools','tools\tunnel-client')) {
    $directory = if ($relative) { Join-Path $expectedRoot $relative } else { $expectedRoot }
    $item = Get-Item -LiteralPath $directory -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'E_PROTECTED_INSTALL_DIRECTORY_INVALID'
    }
    Assert-ProtectedAccessDenied $item.FullName $deleteAccess
    Assert-ProtectedAccessDenied $directory $deleteChildAccess
    foreach ($right in $mutationRights) {
      Assert-ProtectedAccessDenied $item.FullName $right
    }
    $probe = Join-Path $directory ('jdc-custody-probe-' + [guid]::NewGuid().ToString('N'))
    Assert-ProtectedMutationDenied {
      param($state)
      $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
      $state.Changed = $true
      $stream.Dispose()
    } { [IO.File]::Delete($probe) } 'E_PROTECTED_INSTALL_CREATE_ALLOWED'
  }
  # A write denial alone does not imply DELETE/rename denial. Exercise
  # the actual entrypoint and root independently, restoring on unexpected success.
  $entrypoint = Join-Path $expectedRoot 'dist\index.js'
  $movedEntry = $entrypoint + '-probe-' + [guid]::NewGuid().ToString('N')
  Assert-ProtectedMutationDenied {
    param($state)
    [IO.File]::Move($entrypoint, $movedEntry)
    $state.Changed = $true
  } { [IO.File]::Move($movedEntry, $entrypoint) } 'E_PROTECTED_INSTALL_ENTRYPOINT_RENAME_ALLOWED'
  $moved = $expectedRoot + '-probe-' + [guid]::NewGuid().ToString('N')
  Assert-ProtectedMutationDenied {
    param($state)
    [IO.Directory]::Move($expectedRoot, $moved)
    $state.Changed = $true
  } { [IO.Directory]::Move($moved, $expectedRoot) } 'E_PROTECTED_INSTALL_RENAME_ALLOWED'
  $operator = Join-Path $expectedRoot 'jdc-tunnel-operator-ui.exe'
  $process = Start-Process -FilePath $operator -ArgumentList '--check-installation' `
    -WorkingDirectory $expectedRoot -PassThru -Wait
  if ($process.ExitCode -ne 0) { throw 'E_PROTECTED_INSTALL_BACKEND_FAILED' }
  Write-Output 'WINDOWS_PROTECTED_INSTALL_CUSTODY=PASS'
  exit 0
}
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
function Assert-InnoInstallerExitCode {
  param([Parameter(Mandatory)][int]$ExitCode)
  if ($ExitCode -ne 0) {
    # Inno Setup documents the numeric setup exit status, unlike free-form logs.
    [Console]::Error.WriteLine('E_INSTALLER_INNO_EXIT_CODE_' + $ExitCode)
    throw 'E_INSTALLER_INNO_NONZERO_EXIT'
  }
}
$script:AcceptancePhase = 'E_INSTALLER_ACCEPTANCE_PHASE_INSTALL'
$result = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',"/DIR=`"$target`"") -Wait -PassThru
Assert-InnoInstallerExitCode -ExitCode $result.ExitCode
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
Assert-InnoInstallerExitCode -ExitCode $result.ExitCode
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
