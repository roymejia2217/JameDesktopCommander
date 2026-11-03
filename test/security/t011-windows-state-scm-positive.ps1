# T011 C4r — disposable GitHub Windows SCM state-DACL positive/negative kernel proof.
# This script is never a production installer; it must not run on user machines.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $env:ProgramData) {
    throw 'E_C4R_DISPOSABLE_WINDOWS_RUNNER_REQUIRED'
}
$serviceName = 'JameDesktopCommanderAuthority'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'E_C4R_EXISTING_SCM_SERVICE'
}
$sc = (Get-Command sc.exe -ErrorAction Stop).Source
$stage = Join-Path $env:ProgramData ('JDC-T011-C4R-' + [guid]::NewGuid().ToString('N'))
$binDir = Join-Path $stage 'bin'
$state = Join-Path $stage 'state'
$binary = Join-Path $binDir 'windows_state_scm_probe.exe'
$built = Join-Path (Get-Location).Path 'native/authority-service/target/debug/examples/windows_state_scm_probe.exe'
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) {
    throw 'E_C4R_TEST_BINARY_NOT_BUILT'
}
$created = $false
$vhd = Join-Path $env:RUNNER_TEMP ('JDC-T011-C4R-' + [guid]::NewGuid().ToString('N') + '.vhdx')
$isolated = Join-Path $stage 'isolated'
$attached = $false
$admin = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$world = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$modify = [System.Security.AccessControl.FileSystemRights]::Modify
$read = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$inherit = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit

function Set-ExactDirectoryAcl([string] $directory, $serviceSid,
        [System.Security.AccessControl.FileSystemRights] $rights,
        [System.Security.AccessControl.InheritanceFlags] $flags,
        [bool] $foreignAce) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($admin)
    $security.SetAccessRuleProtection($true, $false)
    $principals = @(
        @{ Sid = $system; Rights = $full; Flags = $inherit }
        @{ Sid = $admin; Rights = $full; Flags = $inherit }
        @{ Sid = $serviceSid; Rights = $rights; Flags = $flags }
    )
    if ($foreignAce) {
        $principals += @{ Sid = $world; Rights = $read; Flags = $inherit }
    }
    foreach ($entry in $principals) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Sid, $entry.Rights, $entry.Flags,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $security -ErrorAction Stop
    $actual = Get-Acl -LiteralPath $directory
    if (-not $actual.AreAccessRulesProtected -or
        $actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $admin.Value -or
        $actual.Access.Count -ne $principals.Count) {
        throw 'E_C4R_REAL_ACL_FIXTURE_INVALID'
    }
    foreach ($ace in $actual.Access) {
        if ($ace.IsInherited -or $ace.AccessControlType -ne 'Allow') {
            throw 'E_C4R_REAL_ACL_NOT_EXPLICIT_ALLOW'
        }
    }
}

function Require-ServiceResult([string] $scenario, [int] $expected) {
    # Actual SCM execution is required; a user-shell run cannot report status.
    & $sc start $serviceName | Out-Null
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [timespan]::FromSeconds(15))
    $status = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $status -or $status.State -ne 'Stopped' -or
        $status.ExitCode -ne 1066 -or $status.ServiceSpecificExitCode -ne $expected -or
        $status.ProcessId -ne 0) {
        throw "E_C4R_UNEXPECTED_SCM_RESULT_$scenario (expected=$expected; actual=$($status.ServiceSpecificExitCode); win32=$($status.ExitCode); state=$($status.State))"
    }
}

function Invoke-DisposableDiskPart([string] $commands) {
    $instructions = Join-Path $env:RUNNER_TEMP ('JDC-T011-C4R-' + [guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($instructions, ($commands -replace '\r?\n', "`r`n"))
    try {
        $output = & diskpart.exe /s $instructions 2>&1
        if ($LASTEXITCODE -ne 0 -or
            ($output -match 'Virtual Disk Service error|DiskPart has encountered an error')) {
            throw "E_C4R_DISKPART_FAILED: $($output -join ' | ')"
        }
    } finally {
        Remove-Item -LiteralPath $instructions -Force -ErrorAction SilentlyContinue
    }
}

try {
    New-Item -Path $stage -ItemType Directory -ErrorAction Stop | Out-Null
    New-Item -Path $binDir -ItemType Directory -ErrorAction Stop | Out-Null
    New-Item -Path $state -ItemType Directory -ErrorAction Stop | Out-Null
    & $sc create $serviceName 'type=' 'own' 'start=' 'demand' 'binPath=' $binary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_C4R_SCM_CREATE_FAILED' }
    $created = $true
    & $sc config $serviceName 'obj=' "NT SERVICE\$serviceName" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_C4R_SCM_IDENTITY_CONFIG_FAILED' }
    & $sc sidtype $serviceName restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_C4R_SCM_RESTRICTED_SID_FAILED' }
    $sddl = (Get-Content -LiteralPath 'packaging/experimental/windows/jdc-authority-service.sddl' -Raw).Trim()
    & $sc sdset $serviceName $sddl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_C4R_SCM_DESCRIPTOR_FAILED' }
    $virtual = ([System.Security.Principal.NTAccount]::new("NT SERVICE\$serviceName")).Translate(
        [System.Security.Principal.SecurityIdentifier])

    Set-ExactDirectoryAcl $stage $virtual $read $inherit $false
    Set-ExactDirectoryAcl $binDir $virtual $read $inherit $false
    Set-ExactDirectoryAcl $state $virtual $modify $inherit $false
    Copy-Item -LiteralPath $built -Destination $binary -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) {
        throw 'E_C4R_BINARY_PROVENANCE_MISMATCH'
    }

    # Positive: the true restricted SCM token can open an exact protected DACL.
    Require-ServiceResult 'VALID_PROTECTED_SERVICE_DACL' 41
    # Negative: readable metadata must not be confused with sufficient
    # inherited file-writing permissions for the policy database.
    Set-ExactDirectoryAcl $state $virtual $read $inherit $false
    Require-ServiceResult 'INSUFFICIENT_SERVICE_RIGHTS' 42
    # Positive rebaseline proves the service probe was not just stuck denying.
    Set-ExactDirectoryAcl $state $virtual $modify $inherit $false
    Require-ServiceResult 'RESTORED_PROTECTED_DACL' 41
    Set-ExactDirectoryAcl $state $virtual $modify ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit) $false
    Require-ServiceResult 'MISSING_OBJECT_INHERITANCE' 42
    Set-ExactDirectoryAcl $state $virtual $modify $inherit $true
    Require-ServiceResult 'UNAUTHORIZED_FOREIGN_ACE' 42
    # A real SCM restricted service token must positively observe a separately
    # attached NTFS root, while a same-volume root and weakened root ACL deny.
    # This tests a composed non-shipping observation, NOT an issuer grant.
    Set-ExactDirectoryAcl $state $virtual $modify $inherit $false
    New-Item -Path $isolated -ItemType Directory -ErrorAction Stop | Out-Null
    Set-ExactDirectoryAcl $isolated $virtual $modify $inherit $false
    Require-ServiceResult 'SAME_VOLUME_CANNOT_BIND_ISOLATED_ROOT' 52
    if (Test-Path -LiteralPath $vhd) { throw 'E_C4R_VHD_COLLISION' }
    $vhdSetup = @"
create vdisk file="$vhd" maximum=128 type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=JDC-C4R
assign mount="$isolated"
exit
"@
    Invoke-DisposableDiskPart $vhdSetup
    $diskImage = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
    $attached = [bool]$diskImage.Attached
    if (-not $attached) { throw 'E_C4R_VHD_NOT_ATTACHED' }
    $disk = $diskImage | Get-Disk -ErrorAction Stop
    $systemDisk = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':')).DiskNumber
    if ($disk.Number -eq $systemDisk) { throw 'E_C4R_VHD_SHARED_DISK' }
    $partitions = @($disk | Get-Partition -ErrorAction Stop)
    $mountPath = $isolated.TrimEnd('\') + '\'
    $mountedPartitions = @($partitions | Where-Object {
        @($_.AccessPaths | ForEach-Object { $_.TrimEnd('\') + '\' }) -contains $mountPath
    })
    if ($mountedPartitions.Count -ne 1) {
        throw 'E_C4R_VHD_MOUNT_PATH_NOT_VERIFIED'
    }
    if ((Get-Volume -Partition $mountedPartitions[0]).FileSystem -ne 'NTFS') {
        throw 'E_C4R_VHD_NON_NTFS'
    }
    Set-ExactDirectoryAcl $isolated $virtual $modify $inherit $false
    Require-ServiceResult 'ACTUAL_SCM_TOKEN_WITH_PROTECTED_NTFS_VHD_ROOT' 46
    # A service-writable mountpoint parent could rename or replace the
    # volume namespace entry. Even with a correct isolated root ACL, its
    # administrator-controlled direct parent must be read/traverse-only.
    Set-ExactDirectoryAcl $stage $virtual $modify $inherit $false
    Require-ServiceResult 'SERVICE_MUTABLE_MOUNT_PARENT_DENIED' 53
    Set-ExactDirectoryAcl $stage $virtual $read $inherit $false
    Require-ServiceResult 'ADMINISTRATIVE_MOUNT_PARENT_RESTORED' 46
    Set-ExactDirectoryAcl $isolated $virtual $read $inherit $false
    Require-ServiceResult 'ISOLATED_ROOT_INSUFFICIENT_SERVICE_RIGHTS' 51
    Set-ExactDirectoryAcl $isolated $virtual $modify $inherit $false
    Require-ServiceResult 'ISOLATED_ROOT_ACL_RESTORED' 46
    Set-ExactDirectoryAcl $isolated $virtual $modify $inherit $true
    Require-ServiceResult 'ISOLATED_ROOT_FOREIGN_ACE_DENIED' 51
    Set-ExactDirectoryAcl $isolated $virtual $modify $inherit $false
    Require-ServiceResult 'ISOLATED_ROOT_FINAL_POSITIVE' 46

    Write-Output 'T011-C4r Windows actual restricted SCM state-DACL positive/negative: PASS (non-release)'
    Write-Output 'T011_STORAGE_WINDOWS_ACTUAL_SCM_ISOLATED_VOLUME_COMPOSED_PASS_NONRELEASE'
}
finally {
    $cleanupFailed = $false
    if ($created) {
        & $sc delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { $cleanupFailed = $true }
    }
    # Detach the disposable VHD BEFORE recursively removing its directory
    # mountpoint. On any detach failure, preserve the mounted filesystem and
    # report failure rather than ever recursing through a live volume.
    $volumeStillAttached = $false
    if (Test-Path -LiteralPath $vhd) {
        try {
            $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
            if ($image.Attached) {
                Invoke-DisposableDiskPart @"
select vdisk file="$vhd"
detach vdisk
exit
"@
            }
            $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
            if ($image.Attached) {
                throw 'E_C4R_ISOLATED_VHD_STILL_ATTACHED'
            }
            Remove-Item -LiteralPath $vhd -Force -ErrorAction Stop
        } catch {
            $cleanupFailed = $true
            $volumeStillAttached = $true
        }
    }
    if ((Test-Path -LiteralPath $stage) -and -not $volumeStillAttached) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailed = $true }
    }
    if ($cleanupFailed) { throw 'E_C4R_EPHEMERAL_CLEANUP_FAILED' }
}
