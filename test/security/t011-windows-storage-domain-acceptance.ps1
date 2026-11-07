# T011 #148: temporary NTFS VHD and real OS principals. NON-RELEASE.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $env:RUNNER_TEMP) {
    throw 'E_STORAGE_DOMAIN_HOSTED_WINDOWS_REQUIRED'
}
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
$guid = [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData "JDC-148-STORAGE-$guid"
$vhd = Join-Path $env:RUNNER_TEMP "JDC-148-$guid.vhdx"
$serviceName = "jd148s$($guid.Substring(0,8))"
$attackerName = "jd148a$($guid.Substring(0,8))"
$createdUsers = [System.Collections.Generic.List[string]]::new()
$attached = $false
$letter = @('R','S','T','U','V','W') | Where-Object {
    -not (Test-Path -LiteralPath ("${_}:\"))
} | Select-Object -First 1
if (-not $letter) { throw 'E_STORAGE_NO_FREE_TEMP_DRIVE_LETTER' }
if (Test-Path -LiteralPath $vhd) { throw 'E_STORAGE_VHD_EXISTS' }
function New-CIIdentity([string] $name) {
    $raw = 'Aa1!' + [Convert]::ToBase64String(
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $secure = ConvertTo-SecureString $raw -AsPlainText -Force
    $account = New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -UserMayNotChangePassword
    $script:createdUsers.Add($name)
    return [pscustomobject]@{
        SID = $account.SID
        Credential = [pscredential]::new("$env:COMPUTERNAME\$name", $secure)
    }
}
function Set-CustodyAcl([string] $path, [array] $extra) {
    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true, $false)
    # A fresh NTFS root may contain explicit broad Users/Everyone ACEs;
    # inherited ACE removal alone is not a security boundary.
    foreach ($trustee in @($acl.Access | ForEach-Object { $_.IdentityReference } | Select-Object -Unique)) {
        $acl.PurgeAccessRules($trustee)
    }
    $inherited = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $privileged = @(
        @{ SID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); Rights = 'FullControl' },
        @{ SID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'); Rights = 'FullControl' }
    )
    foreach ($entry in ($privileged + $extra)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $entry.SID, [System.Security.AccessControl.FileSystemRights]$entry.Rights,
            $inherited, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.SetAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    if (-not (Get-Acl -LiteralPath $path).AreAccessRulesProtected) {
        throw 'E_STORAGE_ACL_INHERITANCE_STILL_ON'
    }
}
function Invoke-CIUser([pscredential] $who, [string] $bin, [string[]] $probeArgs) {
    $process = Start-Process -FilePath $bin -Credential $who -ArgumentList $probeArgs -WorkingDirectory $root -PassThru -Wait
    if ($null -eq $process.ExitCode) { throw 'E_STORAGE_MISSING_PROCESS_VERDICT' }
    return [int]$process.ExitCode
}
function Require-UserSuccess([string] $label, [pscredential] $who, [string] $bin, [string[]] $probeArgs) {
    if ((Invoke-CIUser $who $bin $probeArgs) -ne 0) { throw "E_STORAGE_POSITIVE_FAILED_$label" }
}
function Require-UserDenial([string] $label, [pscredential] $who, [string] $bin, [string[]] $probeArgs, [int[]] $expectedOsCodes = @(5)) {
    $stderrFile = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-$label.stderr"
    try {
        $process = Start-Process -FilePath $bin -Credential $who -ArgumentList $probeArgs -WorkingDirectory $root -PassThru -Wait -RedirectStandardError $stderrFile
        if ($null -eq $process.ExitCode) { throw "E_STORAGE_MISSING_PROCESS_VERDICT_$label" }
        if ($process.ExitCode -eq 0) { throw "E_STORAGE_UNAUTHORIZED_$label" }
        $observed = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction Stop).Trim()
        $prefix = if ($probeArgs[0] -ceq 'hardlink') { 'E_HARDLINK_OS_ERROR' } else { 'E_PROBE_OS_ERROR' }
        $accepted = @($expectedOsCodes | ForEach-Object { "${prefix}_$_" })
        if ($accepted -cnotcontains $observed) { throw "E_STORAGE_WRONG_DENIAL_REASON_$label" }
    } finally {
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
}
function Require-AdminCrossVolumeDenial([string] $label, [string] $from, [string] $to) {
    $stderrFile = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-$label.stderr"
    try {
        $attempt = Start-Process -FilePath $probe -ArgumentList @('hardlink', $from, $to) -WorkingDirectory $root -Wait -PassThru -RedirectStandardError $stderrFile
        if ($null -eq $attempt.ExitCode -or $attempt.ExitCode -eq 0) {
            throw "E_STORAGE_ADMIN_CROSS_VOLUME_HARDLINK_ALLOWED_$label"
        }
        $errorCode = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction Stop).Trim()
        if ($errorCode -cne 'E_HARDLINK_OS_ERROR_17') {
            throw "E_STORAGE_WRONG_CROSS_VOLUME_ERROR_$label"
        }
    } finally {
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
}
function Invoke-DiskPart([string] $content) {
    $instructions = Join-Path $env:RUNNER_TEMP "JDC-148-$guid.diskpart.txt"
    [System.IO.File]::WriteAllText($instructions,
        ($content -replace '\r?\n', "`r`n"))
    try {
        $output = & diskpart.exe /s $instructions 2>&1
        if ($LASTEXITCODE -ne 0 -or ($output -match 'Virtual Disk Service error|DiskPart has encountered an error')) {
            throw "E_STORAGE_DISKPART_FAILED: $($output -join ' | ')"
        }
    } finally {
        Remove-Item -LiteralPath $instructions -Force -ErrorAction SilentlyContinue
    }
}
try {
    $service = New-CIIdentity $serviceName
    $attacker = New-CIIdentity $attackerName
    if ($service.SID.Value -eq $attacker.SID.Value) { throw 'E_STORAGE_IDENTICAL_SIDS' }
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($u in @($service, $attacker)) {
        if (@(Get-LocalGroupMember -SID $adminSid).SID.Value -contains $u.SID.Value) {
            throw 'E_STORAGE_ATTACKER_ADMINISTRATOR'
        }
    }
    New-Item -Path $root -ItemType Directory | Out-Null
    $outside = Join-Path $root 'attacker'
    $bin = Join-Path $root 'bin'
    New-Item -Path $outside -ItemType Directory | Out-Null
    New-Item -Path $bin -ItemType Directory | Out-Null
    Set-CustodyAcl $root @(
        @{ SID = $service.SID; Rights = 'ReadAndExecute' },
        @{ SID = $attacker.SID; Rights = 'ReadAndExecute' })
    Set-CustodyAcl $outside @(@{ SID = $attacker.SID; Rights = 'Modify' })
    Set-CustodyAcl $bin @(
        @{ SID = $service.SID; Rights = 'ReadAndExecute' },
        @{ SID = $attacker.SID; Rights = 'ReadAndExecute' })
    $source = Join-Path (Get-Location).Path 'native/authority-store/target/debug/examples/custody_attacker.exe'
    $probe = Join-Path $bin 'custody_attacker.exe'
    Copy-Item -LiteralPath $source -Destination $probe -ErrorAction Stop
    $diskScript = @"
create vdisk file="$vhd" maximum=128 type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=JDC148
assign letter=$letter
exit
"@
    Invoke-DiskPart $diskScript
    $attached = [bool](Get-DiskImage -ImagePath $vhd -ErrorAction Stop).Attached
    if (-not $attached) { throw 'E_STORAGE_VHD_NOT_ATTACHED' }
    $volume = "${letter}:\"
    if (-not (Test-Path -LiteralPath $volume)) { throw 'E_STORAGE_VHD_NO_VOLUME' }
    if ((Get-Volume -DriveLetter $letter).FileSystem -ne 'NTFS') { throw 'E_STORAGE_NOT_NTFS' }
    $outerDisk = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':')).DiskNumber
    $innerDisk = (Get-Partition -DriveLetter $letter).DiskNumber
    if ($outerDisk -eq $innerDisk) { throw 'E_STORAGE_SAME_WINDOWS_DISK' }
    if ((Get-Volume -DriveLetter $env:SystemDrive.TrimEnd(':')).FileSystem -ne 'NTFS') {
        throw 'E_STORAGE_PARENT_NOT_NTFS'
    }
    # This fixture proves kernel/ACL isolation, not native issuer admission.
    # Native root-identity verification is a separate #148 release gate.
    Set-CustodyAcl $volume @(@{ SID = $service.SID; Rights = 'Modify' })
    $serviceFile = Join-Path $volume 'service.bin'
    $outsideFile = Join-Path $outside 'outside.bin'
    Require-UserSuccess 'SERVICE_CAN_WRITE_VOLUME' $service.Credential $probe @('canary', $serviceFile, $serviceFile)
    Require-UserSuccess 'ATTACKER_CAN_WRITE_OWN' $attacker.Credential $probe @('canary', $outsideFile, $outsideFile)
    # Negative control: a missing target is NOT a security denial, even though
    # the probe exits nonzero. This must fail the acceptance gate explicitly.
    $absent = Join-Path $outside 'absent-access-control.bin'
    if (Test-Path -LiteralPath $absent) { throw 'E_STORAGE_ABSENT_CONTROL_EXISTS' }
    try {
        Require-UserDenial 'GATE_REJECTS_MISSING_SOURCE' $attacker.Credential $probe @('read', $absent, $outsideFile)
        throw 'E_STORAGE_MISSING_SOURCE_FALSE_ACCEPTANCE'
    } catch {
        if ($_.Exception.Message -cne 'E_STORAGE_WRONG_DENIAL_REASON_GATE_REJECTS_MISSING_SOURCE') { throw }
    }
    Write-Output 'T011_STORAGE_MISSING_SOURCE_DENIAL_FALSE_POSITIVE_REJECTED'
    $before = (Get-FileHash -LiteralPath $outsideFile -Algorithm SHA256).Hash
    $ownLink = Join-Path $outside 'positive.bin'
    Require-UserSuccess 'ATTACKER_OWN_LINK' $attacker.Credential $probe @('hardlink', $outsideFile, $ownLink)
    Require-UserSuccess 'ATTACKER_SAME_OBJECT' $attacker.Credential $probe @('same-object', $outsideFile, $ownLink)
    Remove-Item -LiteralPath $ownLink -Force
    # Positive real-OS controls: each operation MUST work on attacker-owned
    # storage and service-owned storage before a denial is accepted as custody.
    $attackerControl = Join-Path $outside 'operation-control.bin'
    $attackerSource = Join-Path $outside 'operation-source.bin'
    Require-UserSuccess 'ATTACKER_CONTROL_WRITE' $attacker.Credential $probe @('canary', $attackerControl, $attackerControl)
    Require-UserSuccess 'ATTACKER_CONTROL_SOURCE' $attacker.Credential $probe @('canary', $attackerSource, $attackerSource)
    Require-UserSuccess 'ATTACKER_CONTROL_READ' $attacker.Credential $probe @('read', $attackerControl, $attackerSource)
    Require-UserSuccess 'ATTACKER_CONTROL_APPEND' $attacker.Credential $probe @('append', $attackerControl, $attackerSource)
    Require-UserSuccess 'ATTACKER_CONTROL_REWRITE' $attacker.Credential $probe @('rewrite', $attackerControl, $attackerSource)
    Require-UserSuccess 'ATTACKER_CONTROL_RENAME' $attacker.Credential $probe @('rename', $attackerControl, $attackerSource)
    $attackerRenamed = [IO.Path]::ChangeExtension($attackerControl, '.renamed')
    if (-not (Test-Path -LiteralPath $attackerRenamed)) { throw 'E_STORAGE_CONTROL_RENAME_NOT_OBSERVED' }
    Require-UserSuccess 'ATTACKER_CONTROL_UNLINK' $attacker.Credential $probe @('unlink', $attackerRenamed, $attackerSource)
    Require-UserSuccess 'ATTACKER_CONTROL_CREATE' $attacker.Credential $probe @('create', $attackerControl, $attackerSource)
    if (-not (Test-Path -LiteralPath (Join-Path $outside 'forged.sqlite3'))) {
        throw 'E_STORAGE_CONTROL_CREATE_NOT_OBSERVED'
    }
    $serviceControl = Join-Path $volume 'service-operation-control.bin'
    Require-UserSuccess 'SERVICE_CONTROL_WRITE' $service.Credential $probe @('canary', $serviceControl, $serviceControl)
    Require-UserSuccess 'SERVICE_CONTROL_READ' $service.Credential $probe @('read', $serviceControl, $serviceFile)
    Require-UserSuccess 'SERVICE_CONTROL_APPEND' $service.Credential $probe @('append', $serviceControl, $serviceFile)
    Require-UserSuccess 'SERVICE_CONTROL_REWRITE' $service.Credential $probe @('rewrite', $serviceControl, $serviceFile)
    Require-UserSuccess 'SERVICE_CONTROL_RENAME' $service.Credential $probe @('rename', $serviceControl, $serviceFile)
    $serviceRenamed = [IO.Path]::ChangeExtension($serviceControl, '.renamed')
    if (-not (Test-Path -LiteralPath $serviceRenamed)) { throw 'E_STORAGE_SERVICE_RENAME_NOT_OBSERVED' }
    Require-UserSuccess 'SERVICE_CONTROL_UNLINK' $service.Credential $probe @('unlink', $serviceRenamed, $serviceFile)
    Require-UserSuccess 'SERVICE_CONTROL_CREATE' $service.Credential $probe @('create', $serviceControl, $serviceFile)
    if (-not (Test-Path -LiteralPath (Join-Path $volume 'forged.sqlite3'))) {
        throw 'E_STORAGE_SERVICE_CREATE_NOT_OBSERVED'
    }
    $serviceBefore = (Get-FileHash -LiteralPath $serviceFile -Algorithm SHA256).Hash

    $adminLocalLink = Join-Path $volume 'admin-positive.bin'
    $adminPositive = Start-Process -FilePath $probe -ArgumentList @('hardlink', $serviceFile, $adminLocalLink) -WorkingDirectory $root -Wait -PassThru
    if ($adminPositive.ExitCode -ne 0) { throw 'E_STORAGE_ADMIN_LOCAL_HARDLINK_FAILED' }
    # Keep a kernel-identical, separately named administrator witness until
    # AFTER all malicious operations. Equal final bytes alone cannot detect
    # an inode/file-ID substitution.
    $beforeIdentity = Start-Process -FilePath $probe -ArgumentList @('same-object', $serviceFile, $adminLocalLink) -WorkingDirectory $root -Wait -PassThru
    if ($beforeIdentity.ExitCode -ne 0) { throw 'E_STORAGE_ADMIN_ORIGINAL_IDENTITY_FAILED' }
    Write-Output 'T011_STORAGE_SAME_VOLUME_HARDLINK_PASS'
    # A cross-volume attempt may fail on the device boundary (17) or the
    # protected destination ACL (5), but never on a missing source (2).
    Require-UserDenial 'ATTACKER_VOLUME_LINK' $attacker.Credential $probe @('hardlink', $outsideFile, (Join-Path $volume 'attacker.bin')) @(5, 17)
    Require-UserDenial 'ATTACKER_CANNOT_READ_SERVICE' $attacker.Credential $probe @('read', $serviceFile, $outsideFile)
    Require-UserDenial 'ATTACKER_CANNOT_APPEND_SERVICE' $attacker.Credential $probe @('append', $serviceFile, $outsideFile)
    Require-UserDenial 'ATTACKER_CANNOT_REWRITE_SERVICE' $attacker.Credential $probe @('rewrite', $serviceFile, $outsideFile)
    Require-UserDenial 'ATTACKER_CANNOT_RENAME_SERVICE' $attacker.Credential $probe @('rename', $serviceFile, $outsideFile)
    Require-UserDenial 'ATTACKER_CANNOT_UNLINK_SERVICE' $attacker.Credential $probe @('unlink', $serviceFile, $outsideFile)
    Require-UserDenial 'ATTACKER_CANNOT_CREATE_SERVICE' $attacker.Credential $probe @('create', $serviceFile, $outsideFile)
    if ((Get-FileHash -LiteralPath $serviceFile -Algorithm SHA256).Hash -ne $serviceBefore -or
        (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($serviceFile, '.renamed')))) {
        throw 'E_STORAGE_PROTECTED_OBJECT_CHANGED'
    }
    $afterIdentity = Start-Process -FilePath $probe -ArgumentList @('same-object', $serviceFile, $adminLocalLink) -WorkingDirectory $root -Wait -PassThru
    if ($afterIdentity.ExitCode -ne 0) { throw 'E_STORAGE_PROTECTED_FILE_OBJECT_CHANGED' }
    Remove-Item -LiteralPath $adminLocalLink -Force
    Write-Output 'T011_STORAGE_WINDOWS_READ_REWRITE_APPEND_RENAME_DENIED'
    Require-UserDenial 'ATTACKER_CANNOT_LINK_IN_VOLUME' $attacker.Credential $probe @('hardlink', $serviceFile, (Join-Path $volume 'attacker-internal.bin'))
    # Even an administrator with positive same-volume hardlink rights must
    # receive the kernel's exact cross-device denial, not an unrelated error.
    Require-AdminCrossVolumeDenial 'outside-to-service' $outsideFile (Join-Path $volume 'admin-attempt.bin')
    Require-AdminCrossVolumeDenial 'service-to-outside' $serviceFile (Join-Path $outside 'reverse.bin')
    if ((Test-Path (Join-Path $volume 'attacker.bin')) -or
        (Test-Path (Join-Path $volume 'admin-attempt.bin')) -or
        (Test-Path (Join-Path $volume 'attacker-internal.bin')) -or
        (Test-Path (Join-Path $outside 'reverse.bin'))) {
        throw 'E_STORAGE_UNEXPECTED_CROSS_VOLUME_ALIAS'
    }
    Write-Output 'T011_STORAGE_CROSS_VOLUME_HARDLINK_DENIED'
    if ((Get-FileHash -LiteralPath $outsideFile -Algorithm SHA256).Hash -ne $before) {
        throw 'E_STORAGE_EXTERIOR_BYTES_CHANGED'
    }
    Write-Output 'T011_STORAGE_EXTERIOR_BYTES_UNCHANGED'
    Write-Output 'T011_STORAGE_WINDOWS_DOMAIN_PASS_NONRELEASE'
} finally {
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $vhd) {
        try { Invoke-DiskPart "select vdisk file=`"$vhd`"`ndetach vdisk`nexit" }
        catch { $cleanupErrors.Add('VHD_DETACH') }
    }
    if (Test-Path -LiteralPath $vhd) {
        try { Remove-Item -LiteralPath $vhd -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add('VHD_REMOVE') }
    }
    if (Test-Path -LiteralPath $root) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add('ROOT_REMOVE') }
    }
    foreach ($name in $createdUsers) {
        try { Remove-LocalUser -Name $name -ErrorAction Stop }
        catch { $cleanupErrors.Add('ACCOUNT_REMOVE') }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw "E_STORAGE_CLEANUP_FAILED_$($cleanupErrors -join '_')"
    }
}
