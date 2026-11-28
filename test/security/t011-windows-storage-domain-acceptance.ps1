# T011 #148: temporary NTFS VHD and real OS principals. NON-RELEASE.
param([switch] $ScmStorageOnly, [switch] $StorageDomainOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($StorageDomainOnly -and $ScmStorageOnly) { throw 'E_STORAGE_CONFLICTING_MODES' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $env:RUNNER_TEMP) {
    throw 'E_STORAGE_DOMAIN_HOSTED_WINDOWS_REQUIRED'
}
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
$guid = [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData "JDC-148-STORAGE-$guid"
$imageDir = Join-Path $root 'backing-image'
$vhd = Join-Path $imageDir "JDC-148-$guid.vhdx"
$vhdDetached = $false
$rootOwned = $false
$imageTransitionAttempted = $false
$processStateUncertain = $false
$ownedProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$serviceName = "jd148s$($guid.Substring(0,8))"
$attackerName = "jd148a$($guid.Substring(0,8))"
$clientName = "jd148c$($guid.Substring(0,8))"
$peerServer = $null
$peerLog = $null
$peerReadyWatcher = $null
$peerReadySourceId = "JDC.T011.PeerReady.$guid"
$createdUsers = [System.Collections.Generic.List[string]]::new()
$attached = $false
$admissionAlias = $null
$admissionAliasAttached = $false
$admissionAliasTarget = $null
$primaryFailure = $null
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
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
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
# The child is a disposable test-owned process, not a CI job or installed
# service. A bounded event wait ensures a hung probe cannot block teardown.
function Wait-FixtureProcess([System.Diagnostics.Process] $process, [int] $milliseconds = 12000) {
    if (-not $script:ownedProcesses.Contains($process)) { $script:ownedProcesses.Add($process) }
    if (-not $process.WaitForExit($milliseconds)) {
        if (-not $process.HasExited) { $process.Kill() }
        if (-not $process.WaitForExit(3000)) { throw 'E_STORAGE_FIXTURE_CHILD_NOT_STOPPED' }
        throw 'E_STORAGE_FIXTURE_CHILD_TIMEOUT'
    }
    if ($null -eq $process.ExitCode) { throw 'E_STORAGE_MISSING_PROCESS_VERDICT' }
}
function Confirm-FixtureProcessesStopped {
    foreach ($child in $script:ownedProcesses) {
        try {
            if (-not $child.HasExited) {
                $child.Kill()
                if (-not $child.WaitForExit(3000)) { throw 'E_STORAGE_FIXTURE_CHILD_NOT_STOPPED' }
            }
        } catch {
            $script:processStateUncertain = $true
        }
    }
    if ($script:processStateUncertain) { throw 'E_STORAGE_FIXTURE_PROCESS_STATE_UNCERTAIN' }
}
# Exact Win32 self-relative descriptor retrieval. Get-Acl and the .NET
# CommonSecurityDescriptor normalize some raw ACEs before serialization.
function Initialize-RawBackingSecurity {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
public static class JdcHostedBackingSecurity {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSecurityW(string path, uint flags, [Out] byte[] data, uint size, out uint required);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileSecurityW(string path, uint flags, byte[] data);
    public static byte[] Read(string path) {
        // OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        uint needed;
        bool ok = GetFileSecurityW(path, 5, null, 0, out needed);
        int error = Marshal.GetLastWin32Error();
        if (ok || error != 122 || needed < 20 || needed > 131072)
            throw new InvalidOperationException("E_STORAGE_RAW_DESCRIPTOR_SIZE");
        byte[] buffer = new byte[needed];
        if (!GetFileSecurityW(path, 5, buffer, (uint)buffer.Length, out needed) || needed != buffer.Length)
            throw new InvalidOperationException("E_STORAGE_RAW_DESCRIPTOR_READ");
        return buffer;
    }
    // Used only on a uniquely created disposable regression file, never
    // to grant access to a domain or repair a failed backing ACL.
    public static void SetFixtureDacl(string path, byte[] data) {
        if (!SetFileSecurityW(path, 4, data))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
}
function Assert-IssuerBackingAcl([string] $path, [bool] $directory) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne $directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'E_STORAGE_BACKING_TYPE' }
    $bytes = [JdcHostedBackingSecurity]::Read($path)
    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
    $owner = $raw.Owner.Value
    $issuer = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $protected = [bool]($raw.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    if ($owner -notin @('S-1-5-18','S-1-5-32-544',$issuer) -or
        $protected -ne $directory) { throw 'E_STORAGE_BACKING_OWNER_OR_PROTECTION' }
    Assert-IssuerRawDacl $bytes $directory
}
function Assert-IssuerRawDacl([byte[]] $descriptor, [bool] $directory) {
    # GetAccessRules may project a callback ACE as an ordinary allow rule.
    # Inspect every raw ACE, including its type and flags.
    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0)
    $dacl = $raw.DiscretionaryAcl
    $expectedFlags = if ($directory) { 3 } else { 16 }
    $trustees = @('S-1-5-18','S-1-5-32-544')
    if ($null -eq $dacl -or $dacl.Count -ne 2) { throw 'E_STORAGE_VHD_BACKING_ACL_UNSAFE' }
    $seen = @()
    foreach ($ace in $dacl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed -or
            $ace -isnot [System.Security.AccessControl.CommonAce] -or
            $ace.IsCallback -or $ace.AccessMask -ne 0x1f01ff -or
            [int]$ace.AceFlags -ne $expectedFlags -or
            $ace.SecurityIdentifier.Value -notin $trustees -or
            $seen -contains $ace.SecurityIdentifier.Value) { throw 'E_STORAGE_VHD_BACKING_ACL_UNSAFE' }
        $seen += $ace.SecurityIdentifier.Value
    }
}
# A pure descriptor regression, before any fixture account or disk creation.
# In particular a callback ACE with the same SID/mask/flags must not pass.
function Test-IssuerRawDaclContract {
    foreach ($directory in @($true,$false)) {
        $flags = if ($directory) { 'OICI' } else { 'ID' }
        $control = if ($directory) { 'P' } else { 'AI' }
        $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            "O:BAD:$control(A;$flags;0x1f01ff;;;BA)(A;$flags;0x1f01ff;;;SY)")
        $bytes = [byte[]]::new($sd.BinaryLength)
        $sd.GetBinaryForm($bytes, 0)
        Assert-IssuerRawDacl $bytes $directory
        $original = $sd.DiscretionaryAcl[0]
        $callback = [System.Security.AccessControl.CommonAce]::new(
            $original.AceFlags, [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            $original.AccessMask, $original.SecurityIdentifier, $true, [byte[]](0,0,0,0))
        $sd.DiscretionaryAcl.RemoveAce(0)
        $sd.DiscretionaryAcl.InsertAce(0, $callback)
        $bytes = [byte[]]::new($sd.BinaryLength)
        $sd.GetBinaryForm($bytes, 0)
        $denied = $false
        try { Assert-IssuerRawDacl $bytes $directory }
        catch {
            if ($_.Exception.Message -ne 'E_STORAGE_VHD_BACKING_ACL_UNSAFE') { throw }
            $denied = $true
        }
        if (-not $denied) { throw 'E_STORAGE_CALLBACK_ACE_ACCEPTED' }
    }
    Write-Output 'T011_WINDOWS_BACKING_RAW_DACL_CONTRACT_PASS_NONRELEASE'
}
function Test-IssuerRawDaclRetrieval {
    # The backing directory is already admitted. Exercise the exact retrieval
    # path on a new file whose inherited DACL is identical to the VHDX contract.
    Assert-IssuerBackingAcl $imageDir $true
    $path = Join-Path $imageDir ('acl-regression-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
    $original = [JdcHostedBackingSecurity]::Read($path)
    try {
        Assert-IssuerBackingAcl $path $false
        $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($original, 0)
        $zero = [System.Security.AccessControl.CommonAce]::new(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed, 0,
            [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), $false, $null)
        $sd.DiscretionaryAcl.InsertAce(0, $zero)
        $bytes = [byte[]]::new($sd.BinaryLength)
        $sd.GetBinaryForm($bytes, 0)
        [JdcHostedBackingSecurity]::SetFixtureDacl($path, $bytes)
        $observed = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            [JdcHostedBackingSecurity]::Read($path), 0)
        $zeros = @($observed.DiscretionaryAcl | Where-Object {
            $_.AceType -eq 'AccessAllowed' -and $_.AccessMask -eq 0 -and
            $_.SecurityIdentifier.Value -eq 'S-1-1-0'
        })
        if ($observed.DiscretionaryAcl.Count -ne 3 -or $zeros.Count -ne 1) {
            throw 'E_STORAGE_RAW_ZERO_ACE_NOT_OBSERVED'
        }
        $denied = $false
        try { Assert-IssuerBackingAcl $path $false }
        catch {
            if ($_.Exception.Message -ne 'E_STORAGE_VHD_BACKING_ACL_UNSAFE') { throw }
            $denied = $true
        }
        if (-not $denied) { throw 'E_STORAGE_RAW_ZERO_ACE_ACCEPTED' }
    } finally {
        [JdcHostedBackingSecurity]::SetFixtureDacl($path, $original)
        Assert-IssuerBackingAcl $path $false
        Remove-Item -LiteralPath $path -ErrorAction Stop
    }
    Write-Output 'T011_WINDOWS_BACKING_RAW_DESCRIPTOR_RETRIEVAL_PASS_NONRELEASE'
}
function Invoke-CIUser([pscredential] $who, [string] $bin, [string[]] $probeArgs) {
    $process = Start-Process -FilePath $bin -Credential $who -ArgumentList $probeArgs -WorkingDirectory $root -PassThru
    Wait-FixtureProcess $process
    if ($null -eq $process.ExitCode) { throw 'E_STORAGE_MISSING_PROCESS_VERDICT' }
    return [int]$process.ExitCode
}
function Require-UserSuccess([string] $label, [pscredential] $who, [string] $bin, [string[]] $probeArgs) {
    if ((Invoke-CIUser $who $bin $probeArgs) -ne 0) { throw "E_STORAGE_POSITIVE_FAILED_$label" }
}
function Require-UserDenial([string] $label, [pscredential] $who, [string] $bin, [string[]] $probeArgs, [int[]] $expectedOsCodes = @(5)) {
    $stderrFile = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-$label.stderr"
    try {
        $process = Start-Process -FilePath $bin -Credential $who -ArgumentList $probeArgs -WorkingDirectory $root -PassThru -RedirectStandardError $stderrFile
        Wait-FixtureProcess $process
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
        $attempt = Start-Process -FilePath $probe -ArgumentList @('hardlink', $from, $to) -WorkingDirectory $root -PassThru -RedirectStandardError $stderrFile
        Wait-FixtureProcess $attempt
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
    # The elevated command file is authority-bearing, just like the VHDX.
    # Never source it from a shared runner-temporary directory.
    Assert-IssuerBackingAcl $imageDir $true
    $instructions = Join-Path $imageDir ("diskpart-" + [guid]::NewGuid().ToString('N') + '.txt')
    $diskProcess = $null
    $created = $false
    try {
        $stream = [IO.File]::Open($instructions, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $created = $true
        try {
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($content -replace '\r?\n', "`r`n"))
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        Assert-IssuerBackingAcl $instructions $false
        $outLog = "$instructions.stdout"
        $errLog = "$instructions.stderr"
        $diskpart = Join-Path ([Environment]::SystemDirectory) 'diskpart.exe'
        $diskProcess = Start-Process -FilePath $diskpart -ArgumentList @('/s', ('"' + $instructions + '"')) -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog
        Wait-FixtureProcess $diskProcess 60000
        $output = @(Get-Content -LiteralPath $outLog) + @(Get-Content -LiteralPath $errLog)
        if ($diskProcess.ExitCode -ne 0 -or ($output -match 'Virtual Disk Service error|DiskPart has encountered an error')) {
            throw 'E_STORAGE_DISKPART_FAILED'
        }
    } finally {
        if ($created -and ($null -eq $diskProcess -or $diskProcess.HasExited)) {
            Remove-Item -LiteralPath $instructions,"$instructions.stdout","$instructions.stderr" -Force -ErrorAction SilentlyContinue
        }
    }
}
# Use the Windows Storage provider directly. Never parse localized command
# output or delete a mount without proving which partition owns the path.
function Get-AdmissionPartition([string] $targetGuid) {
    $partitions = @(Get-Partition -ErrorAction Stop | Where-Object {
        $_.AccessPaths -contains $targetGuid
    })
    if ($partitions.Count -ne 1) { throw 'E_STORAGE_ALIAS_TARGET_UNVERIFIABLE' }
    return $partitions[0]
}
function Get-AdmissionAliasOwner {
    $path = $admissionAlias.TrimEnd('\')
    $owners = @(Get-Partition -ErrorAction Stop | Where-Object {
        @($_.AccessPaths | Where-Object { $_ -and $_.TrimEnd('\') -ieq $path }).Count -gt 0
    })
    if ($owners.Count -gt 1) { throw 'E_STORAGE_ALIAS_TARGET_MISMATCH' }
    if ($owners.Count -eq 1) { return $owners[0] }
}
function Confirm-AdmissionAliasRemoved {
    if ($null -ne (Get-AdmissionAliasOwner)) { throw 'E_STORAGE_ADMISSION_ALIAS_REMOVAL_UNVERIFIED' }
    $item = Get-Item -LiteralPath $admissionAlias.TrimEnd('\') -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'E_STORAGE_ALIAS_UNPROVEN_REPARSE'
    }
    $script:admissionAliasAttached = $false
    $script:admissionAliasTarget = $null
}
function Add-AdmissionAlias([string] $targetGuid) {
    # Until absence is proven, even a pre-existing reparse point prevents
    # recursive cleanup. No target is owned before that initial check.
    $script:admissionAliasAttached = $true
    $script:admissionAliasTarget = $null
    Confirm-AdmissionAliasRemoved
    $partition = Get-AdmissionPartition $targetGuid
    # Mark uncertainty before invoking the provider. A failed call may have
    # changed state; cleanup must re-observe the actual partition ownership.
    $script:admissionAliasTarget = $targetGuid
    $script:admissionAliasAttached = $true
    try {
        Add-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -AccessPath $admissionAlias -ErrorAction Stop | Out-Null
    } catch {
        throw "E_STORAGE_ALIAS_ADD_HRESULT_$('{0:X8}' -f $_.Exception.HResult)"
    }
    $owner = Get-AdmissionAliasOwner
    if ($null -eq $owner -or $owner.AccessPaths -notcontains $targetGuid) {
        throw 'E_STORAGE_ALIAS_TARGET_MISMATCH'
    }
    $item = Get-Item -LiteralPath $admissionAlias.TrimEnd('\') -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'E_STORAGE_ADMISSION_ALIAS_NOT_PROVEN'
    }
}
function Remove-AdmissionAlias {
    $owner = Get-AdmissionAliasOwner
    if ($null -ne $owner) {
        if (-not $admissionAliasTarget -or $owner.AccessPaths -notcontains $admissionAliasTarget) {
            throw 'E_STORAGE_ALIAS_TARGET_MISMATCH'
        }
        $partition = Get-AdmissionPartition $admissionAliasTarget
        if ($owner.DiskNumber -ne $partition.DiskNumber -or $owner.PartitionNumber -ne $partition.PartitionNumber) {
            throw 'E_STORAGE_ALIAS_TARGET_MISMATCH'
        }
        try {
            Remove-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -AccessPath $admissionAlias -ErrorAction Stop
        } catch {
            throw "E_STORAGE_ALIAS_REMOVE_HRESULT_$('{0:X8}' -f $_.Exception.HResult)"
        }
    }
    # Failed creation with no actual mount is not a removal failure. Unknown
    # reparse points are never traversed or deleted by the fixture cleanup.
    Confirm-AdmissionAliasRemoved
}
# Coordinate a real, already-open service owner with a trusted mount-manager
# transition using redirected standard streams, not a client grant or polling.
function Invoke-ActiveAdmissionAliasProbe([string] $targetGuid,
    [ValidateSet('mount-paths-not-exclusive','nested-mount-present')][string] $expectedCheck) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $admissionProbe
    $info.Arguments = '--ignored --exact journaled_mutations::tests::hosted_verified_volume_active_owner_rejects_alias --nocapture'
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.UserName = $serviceName
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $service.Credential.Password
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $child = [System.Diagnostics.Process]::new()
    $child.StartInfo = $info
    $started = $false
    try {
        if (-not $child.Start()) { throw 'E_STORAGE_ACTIVE_OWNER_START' }
        $started = $true
        $script:ownedProcesses.Add($child)
        $errors = $child.StandardError.ReadToEndAsync()
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $ready = $false
        # Each iteration blocks for a new output line, under one deadline.
        # This is not a repeated status check.
        while (-not $ready) {
            $remaining = 12000 - [int]$clock.ElapsedMilliseconds
            if ($remaining -le 0) { throw 'E_STORAGE_ACTIVE_OWNER_READY_TIMEOUT' }
            $line = $child.StandardOutput.ReadLineAsync()
            if (-not $line.Wait($remaining) -or $null -eq $line.Result) {
                throw 'E_STORAGE_ACTIVE_OWNER_READY_FAILED'
            }
            $ready = $line.Result -ceq 'T011_WINDOWS_ACTIVE_VOLUME_OWNER_READY_NONRELEASE'
        }
        Add-AdmissionAlias $targetGuid
        $child.StandardInput.WriteLine('CHECK')
        $child.StandardInput.Flush()
        $child.StandardInput.Close()
        $output = $child.StandardOutput.ReadToEndAsync()
        Wait-FixtureProcess $child 30000
        if (-not $output.Wait(3000) -or -not $errors.Wait(3000)) { throw 'E_STORAGE_ACTIVE_OWNER_STREAM_TIMEOUT' }
        $lines = @($output.Result -split '\r?\n')
        if ($child.ExitCode -ne 0 -or
            $lines -cnotcontains 'T011_WINDOWS_ACTIVE_VOLUME_ALIAS_DENIED_NONRELEASE' -or
            -not ($lines -match '^test result: ok[.] 1 passed; 0 failed; 0 ignored;')) {
            throw 'E_STORAGE_ACTIVE_OWNER_ALIAS_CHECK_FAILED'
        }
        $diagnostics = @($errors.Result -split '\r?\n')
        if ($diagnostics -cnotcontains "T011_WINDOWS_VOLUME_ADMISSION_DENIED check=$expectedCheck os_code=None") {
            throw 'E_STORAGE_ACTIVE_OWNER_WRONG_TOPOLOGY_DENIAL'
        }
        Write-Output 'T011_WINDOWS_ACTIVE_VOLUME_ALIAS_DENIED_NONRELEASE'
    } finally {
        if ($started -and -not $child.HasExited) {
            $child.Kill()
            if (-not $child.WaitForExit(3000)) { throw 'E_STORAGE_ACTIVE_OWNER_NOT_STOPPED' }
        }
        if (-not $started) { $child.Dispose() }
    }
}
function Invoke-AdmissionProbe([string] $testName, [string] $marker, [pscredential] $who = $service.Credential) {
    $log = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-admission-$([guid]::NewGuid().ToString('N')).stdout"
    $errLog = "$log.stderr"
    try {
        $launch = @{
            FilePath = $admissionProbe
            WorkingDirectory = $root
            ArgumentList = @('--ignored', '--exact', $testName, '--nocapture')
            PassThru = $true
            RedirectStandardOutput = $log
            RedirectStandardError = $errLog
        }
        if ($null -ne $who) { $launch.Credential = $who }
        $process = Start-Process @launch
        Wait-FixtureProcess $process 30000
        $lines = @(Get-Content -LiteralPath $log)
        if ($null -eq $process.ExitCode -or $process.ExitCode -ne 0 -or $lines -cnotcontains $marker -or
            -not ($lines -match '^test result: ok[.] 1 passed; 0 failed; 0 ignored;')) {
            $lines | Write-Output
            Get-Content -LiteralPath $errLog | Write-Output
            throw 'E_STORAGE_NATIVE_ADMISSION_TEST_FAILED'
        }
        Write-Output $marker
    } finally {
        Remove-Item -LiteralPath $log,$errLog -Force -ErrorAction SilentlyContinue
    }
}
function Invoke-PeerClient([pscredential] $who, [string] $proof, [string] $mode,
    [string] $pipeName, [string] $expectedMarker) {
    $log = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-peer-$mode-$([guid]::NewGuid().ToString('N')).stderr"
    $process = $null
    try {
        $process = Start-Process -FilePath $proof -Credential $who -ArgumentList @($mode, $pipeName) -WorkingDirectory $root -PassThru -RedirectStandardError $log
        $script:ownedProcesses.Add($process)
        if (-not $process.WaitForExit(12000)) { throw "E_PIPE_CLIENT_TIMEOUT_$mode" }
        if ($process.ExitCode -ne 0) {
            # Preserve only an explicitly classified machine error, not
            # arbitrary process stderr, paths, SIDs or credentials.
            $reasons = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue |
                Where-Object { $_ -cmatch '^E_PIPE_[A-Z0-9_]+$' })
            $reason = if ($reasons.Count -eq 1) { $reasons[0] } else { 'NO_SAFE_DIAGNOSTIC' }
            throw "E_PIPE_CLIENT_FAILED_$($mode)_$reason"
        }
        if (-not (Select-String -LiteralPath $log -SimpleMatch $expectedMarker -Quiet)) {
            throw "E_PIPE_CLIENT_MISSING_VERDICT_$mode"
        }
    } finally {
        if ($null -ne $process -and -not $process.HasExited) {
            $process.Kill()
            if (-not $process.WaitForExit(3000)) { throw 'E_PIPE_CLIENT_CLEANUP_FAILED' }
        }
        Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    }
}
try {
    Initialize-RawBackingSecurity
    Test-IssuerRawDaclContract
    # Establish a newly created, administrator-owned parent BEFORE any
    # test identities exist. Never claim or recursively delete a prior path.
    if (Test-Path -LiteralPath $root) { throw 'E_STORAGE_FIXTURE_ROOT_EXISTS' }
    New-Item -Path $root -ItemType Directory -ErrorAction Stop | Out-Null
    $rootOwned = $true
    Set-CustodyAcl $root @()
    Assert-IssuerBackingAcl $root $true
    New-Item -Path $imageDir -ItemType Directory -ErrorAction Stop | Out-Null
    Set-CustodyAcl $imageDir @()
    Assert-IssuerBackingAcl $imageDir $true
    Test-IssuerRawDaclRetrieval
    $service = New-CIIdentity $serviceName
    $attacker = New-CIIdentity $attackerName
    $client = New-CIIdentity $clientName
    if ($service.SID.Value -eq $attacker.SID.Value -or
        $service.SID.Value -eq $client.SID.Value -or
        $client.SID.Value -eq $attacker.SID.Value) { throw 'E_STORAGE_IDENTICAL_SIDS' }
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($u in @($service, $attacker, $client)) {
        if (@(Get-LocalGroupMember -SID $adminSid).SID.Value -contains $u.SID.Value) {
            throw 'E_STORAGE_ATTACKER_ADMINISTRATOR'
        }
    }
    $outside = Join-Path $root 'attacker'
    $bin = Join-Path $root 'bin'
    $readyDir = Join-Path $root 'peer-ready'
    New-Item -Path $outside -ItemType Directory | Out-Null
    New-Item -Path $bin -ItemType Directory | Out-Null
    New-Item -Path $readyDir -ItemType Directory | Out-Null
    Set-CustodyAcl $root @(
        @{ SID = $service.SID; Rights = 'ReadAndExecute' },
        @{ SID = $attacker.SID; Rights = 'ReadAndExecute' },
        @{ SID = $client.SID; Rights = 'ReadAndExecute' })
    # The virtual disk backing file inherits administrator/SYSTEM-only
    # custody before it exists. No independent test principal gets access.
    Assert-IssuerBackingAcl $imageDir $true
    Set-CustodyAcl $outside @(@{ SID = $attacker.SID; Rights = 'Modify' })
    Set-CustodyAcl $readyDir @(@{ SID = $service.SID; Rights = 'Modify' })
    Set-CustodyAcl $bin @(
        @{ SID = $service.SID; Rights = 'ReadAndExecute' },
        @{ SID = $attacker.SID; Rights = 'ReadAndExecute' },
        @{ SID = $client.SID; Rights = 'ReadAndExecute' })
    $source = Join-Path (Get-Location).Path 'native/authority-store/target/debug/examples/custody_attacker.exe'
    $probe = Join-Path $bin 'custody_attacker.exe'
    Copy-Item -LiteralPath $source -Destination $probe -ErrorAction Stop
    # Creation and attachment are separate operations. Validate file
    # custody while it is detached, before a destructive disk operation.
    $createScript = @"
create vdisk file="$vhd" maximum=128 type=expandable
exit
"@
    $imageTransitionAttempted = $true
    Invoke-DiskPart $createScript
    Assert-IssuerBackingAcl $vhd $false
    Require-UserDenial 'ATTACKER_READ_VHD_BACKING' $attacker.Credential $probe @('read', $vhd, $vhd)
    Require-UserDenial 'CLIENT_READ_VHD_BACKING' $client.Credential $probe @('read', $vhd, $vhd)
    Require-UserDenial 'SERVICE_READ_VHD_BACKING' $service.Credential $probe @('read', $vhd, $vhd)
    $attachScript = @"
select vdisk file="$vhd"
attach vdisk
exit
"@
    Invoke-DiskPart $attachScript
    $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
    $attached = [bool]$image.Attached
    if (-not $attached) { throw 'E_STORAGE_VHD_NOT_ATTACHED' }
    $verifiedDisks = @($image | Get-Disk -ErrorAction Stop)
    if ($verifiedDisks.Count -ne 1) { throw 'E_STORAGE_VHD_DISK_IDENTITY_UNAVAILABLE' }
    $verifiedDisk = $verifiedDisks[0]
    $verifiedNumber = [uint32]$verifiedDisk.Number
    if ($verifiedDisk.IsBoot -or $verifiedDisk.IsSystem -or $verifiedDisk.NumberOfPartitions -ne 0 -or
        $verifiedDisk.Size -ne 128MB -or $verifiedDisk.PartitionStyle -ne 'RAW' -or
        $verifiedNumber -eq (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':')).DiskNumber -or
        (Test-Path -LiteralPath ("${letter}:\"))) { throw 'E_STORAGE_VHD_UNSAFE_DISK' }
    # Resolve the exact image again immediately before selecting the disk.
    $current = @(Get-DiskImage -ImagePath $vhd -ErrorAction Stop | Get-Disk -ErrorAction Stop)
    if ($current.Count -ne 1 -or $current[0].Number -ne $verifiedNumber -or
        $current[0].UniqueId -ne $verifiedDisk.UniqueId -or $current[0].IsBoot -or $current[0].IsSystem -or
        $current[0].NumberOfPartitions -ne 0) { throw 'E_STORAGE_VHD_DISK_IDENTITY_CHANGED' }
    $partitionScript = @"
select disk $verifiedNumber
create partition primary
format fs=ntfs quick label=JDC148
assign letter=$letter
exit
"@
    Invoke-DiskPart $partitionScript
    $volume = "${letter}:\"
    if (-not (Test-Path -LiteralPath $volume)) { throw 'E_STORAGE_VHD_NO_VOLUME' }
    if ((Get-Volume -DriveLetter $letter).FileSystem -ne 'NTFS') { throw 'E_STORAGE_NOT_NTFS' }
    $outerDisk = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':')).DiskNumber
    $innerDisk = (Get-Partition -DriveLetter $letter).DiskNumber
    $imageDisks = @($image | Get-Disk -ErrorAction Stop)
    if ($imageDisks.Count -ne 1 -or $imageDisks[0].Number -ne $innerDisk) {
        throw 'E_STORAGE_VHD_DISK_IDENTITY_MISMATCH'
    }
    if ($outerDisk -eq $innerDisk) { throw 'E_STORAGE_SAME_WINDOWS_DISK' }
    Assert-IssuerBackingAcl $imageDir $true
    Assert-IssuerBackingAcl $vhd $false
    Write-Output 'T011_WINDOWS_VHD_BACKING_CUSTODY_PASS_NONRELEASE'
    if ((Get-Volume -DriveLetter $env:SystemDrive.TrimEnd(':')).FileSystem -ne 'NTFS') {
        throw 'E_STORAGE_PARENT_NOT_NTFS'
    }
    Set-CustodyAcl $volume @(@{ SID = $service.SID; Rights = 'Modify' })
    # Administrator-provisioned volume and immutable test inputs.
    $volumeGuids = @((Get-Partition -DriveLetter $letter).AccessPaths | Where-Object {
        $_ -match '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'
    })
    if ($volumeGuids.Count -ne 1) { throw 'E_STORAGE_VOLUME_GUID_UNAVAILABLE' }
    $volumeGuid = $volumeGuids[0]
    $volumeOwner = (Get-Acl -LiteralPath $volume).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($ScmStorageOnly) {
        # Separate freshly provisioned VHD. Never reuse the legacy domain or
        # detach while a service may still hold its object handles.
        $scmOutside = Join-Path $outside 'scm-outside.bin'
        Require-UserSuccess 'SCM_ATTACKER_OWN_POSITIVE' $attacker.Credential $probe @('canary', $scmOutside, $scmOutside)
        $outsideBefore = (Get-FileHash -LiteralPath $scmOutside -Algorithm SHA256).Hash
        $processStateUncertain = $true
        & (Join-Path (Get-Location).Path 'test/security/t011-windows-scm-acceptance.ps1') -StorageDrive $volume -StorageGuid $volumeGuid -StorageImage $vhd | Tee-Object -Variable scmResult
        if ((Get-Service -Name 'JameDesktopCommanderAuthority' -ErrorAction SilentlyContinue) -or
            (Get-Service -Name 'JameDesktopCommanderIssuer' -ErrorAction SilentlyContinue)) {
            throw 'E_STORAGE_SCM_CLEANUP_UNVERIFIED'
        }
        $processStateUncertain = $false
        if ($scmResult -cnotcontains 'T011_WINDOWS_SCM_ADMITTED_SDK_MUTATIONS_PASS_NONRELEASE' -or
            $scmResult -cnotcontains 'T011_WINDOWS_SCM_ADMITTED_SDK_CANCEL_REPLAY_PASS_NONRELEASE') {
            throw 'E_STORAGE_SCM_ADMITTED_VERDICT_MISSING'
        }
        Assert-IssuerBackingAcl $imageDir $true
        Assert-IssuerBackingAcl $vhd $false
        $final = Join-Path $volume 'final.txt'
        $db = Join-Path $volume '.jdc-state/policy.sqlite3'
        $aux = Join-Path $bin 'scm-aux.bin'
        [IO.File]::WriteAllBytes($aux, [Text.Encoding]::ASCII.GetBytes('SCM_NEGATIVE_CONTROL'))
        $finalBefore = (Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash
        $dbBefore = (Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash
        foreach ($principal in @(
            @{ Label = 'ATTACKER'; Identity = $attacker.Credential },
            @{ Label = 'CLIENT'; Identity = $client.Credential },
            @{ Label = 'OLD_SERVICE'; Identity = $service.Credential }
        )) {
            # A rewrite denial cannot be attributed to an inaccessible source.
            Require-UserSuccess ("SCM_" + $principal.Label + "_READ_AUX") $principal.Identity $probe @('read', $aux, $aux)
            foreach ($operation in @('read', 'append', 'rewrite', 'rename', 'unlink')) {
                Require-UserDenial ("SCM_" + $principal.Label + "_FINAL_" + $operation.ToUpperInvariant()) $principal.Identity $probe @($operation, $final, $aux)
                Require-UserDenial ("SCM_" + $principal.Label + "_JOURNAL_" + $operation.ToUpperInvariant()) $principal.Identity $probe @($operation, $db, $aux)
            }
            Require-UserDenial ("SCM_" + $principal.Label + "_CREATE") $principal.Identity $probe @('create', $final, $scmOutside)
        }
        Require-AdminCrossVolumeDenial 'scm-outside-to-domain' $scmOutside (Join-Path $volume 'scm-admin-link.bin')
        Require-AdminCrossVolumeDenial 'scm-domain-to-outside' $final (Join-Path $outside 'scm-reverse-link.bin')
        if ((Get-FileHash -LiteralPath $scmOutside -Algorithm SHA256).Hash -ne $outsideBefore -or
            (Get-FileHash -LiteralPath $final -Algorithm SHA256).Hash -ne $finalBefore -or
            (Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash -ne $dbBefore) {
            throw 'E_STORAGE_SCM_OBJECT_BYTES_CHANGED'
        }
        Write-Output 'T011_WINDOWS_SCM_ADMITTED_OUTSIDE_INTEGRITY_PASS_NONRELEASE'
        return
    }
    $artifactLines = & cargo +1.91.1 test --locked --manifest-path native/authority-service/Cargo.toml --lib --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'E_STORAGE_ADMISSION_BUILD_FAILED' }
    $artifacts = @($artifactLines | ForEach-Object { ConvertFrom-Json -InputObject $_ } | Where-Object {
        $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'jdc_authority_service' -and $_.profile.test -eq $true -and $_.executable
    })
    if ($artifacts.Count -ne 1) { throw 'E_STORAGE_ADMISSION_ARTIFACT_AMBIGUOUS' }
    $admissionProbe = Join-Path $bin 'admission-probe.exe'
    Copy-Item -LiteralPath $artifacts[0].executable -Destination $admissionProbe -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $artifacts[0].executable -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $admissionProbe -Algorithm SHA256).Hash) { throw 'E_STORAGE_ADMISSION_ARTIFACT_MISMATCH' }
    [System.IO.File]::WriteAllLines((Join-Path $root 'admission-input.txt'),
        [string[]]@($volume, $volumeGuid, $service.SID.Value, $volumeOwner))
    Invoke-AdmissionProbe 'journaled_mutations::tests::hosted_verified_volume_executes_journaled_native_mutations' 'T011_WINDOWS_ADMITTED_JOURNALED_MUTATIONS_PASS_NONRELEASE'
    $admissionFile = Join-Path $volume 'admission-final.bin'
    $admissionDb = Join-Path $volume '.jdc-state/policy.sqlite3'
    $admissionHash = (Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash
    Require-UserSuccess 'SERVICE_READ_ADMITTED_FILE' $service.Credential $probe @('read', $admissionFile, $admissionFile)
    Require-UserDenial 'ATTACKER_READ_ADMITTED_FILE' $attacker.Credential $probe @('read', $admissionFile, $admissionFile)
    Require-UserDenial 'CLIENT_READ_ADMISSION_DB' $client.Credential $probe @('read', $admissionDb, $admissionDb)
    Require-UserDenial 'ATTACKER_READ_ADMISSION_DB' $attacker.Credential $probe @('read', $admissionDb, $admissionDb)
    if ((Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash -ne $admissionHash) { throw 'E_STORAGE_ADMISSION_DB_CHANGED' }
    $admissionAlias = (Join-Path $root 'admission-alias') + '\'
    New-Item -Path $admissionAlias -ItemType Directory | Out-Null
    # Treat a failed mount request as potentially partial until detached;
    # never recurse into a directory that may still be a volume alias.
    Invoke-ActiveAdmissionAliasProbe $volumeGuid 'mount-paths-not-exclusive'
    Invoke-AdmissionProbe 'journaled_mutations::tests::hosted_verified_volume_rejects_alternate_mount' 'T011_WINDOWS_ADMITTED_VOLUME_ALIAS_DENIED_NONRELEASE'
    if ((Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash -ne $admissionHash) { throw 'E_STORAGE_ALIAS_REJECT_CHANGED_DB' }
    Remove-AdmissionAlias
    # Hosted-only outgoing mount: the source directory belongs to our
    # disposable VHD, never the system volume. The existing outside volume
    # is only the mount target; no operation traverses this mounted path.
    # The same cleanup guard must prove removal before VHD detachment.
    $outerVolumeGuids = @((Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':')).AccessPaths | Where-Object {
        $_ -match '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'
    })
    if ($outerVolumeGuids.Count -ne 1 -or $outerVolumeGuids[0] -ieq $volumeGuid) {
        throw 'E_STORAGE_OUTSIDE_VOLUME_GUID_UNAVAILABLE'
    }
    $outerVolumeGuid = $outerVolumeGuids[0]
    $admissionAlias = (Join-Path $volume '.jdc-nested-mount') + '\'
    New-Item -Path $admissionAlias -ItemType Directory -ErrorAction Stop | Out-Null
    Invoke-ActiveAdmissionAliasProbe $outerVolumeGuid 'nested-mount-present'
    if ((Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash -ne $admissionHash) {
        throw 'E_STORAGE_NESTED_MOUNT_REJECT_CHANGED_DB'
    }
    Remove-AdmissionAlias
    [IO.Directory]::Delete($admissionAlias.TrimEnd('\'), $false)
    Write-Output 'T011_WINDOWS_ACTIVE_NESTED_MOUNT_DENIED_NONRELEASE'
    Invoke-AdmissionProbe 'journaled_mutations::tests::hosted_verified_volume_readmits_after_alias_removed' 'T011_WINDOWS_ADMITTED_VOLUME_RESTORED_NONRELEASE'
    $serviceFile = Join-Path $volume 'service.bin'
    $outsideFile = Join-Path $outside 'outside.bin'
    Require-UserSuccess 'SERVICE_CAN_WRITE_VOLUME' $service.Credential $probe @('canary', $serviceFile, $serviceFile)
    Require-UserSuccess 'ATTACKER_CAN_WRITE_OWN' $attacker.Credential $probe @('canary', $outsideFile, $outsideFile)
    # After readmission the database has a new committed sequence. Verify
    # actual native write and namespace denials against this exact state.
    $admissionHash = (Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash
    Require-UserDenial 'ATTACKER_REWRITE_ADMISSION_DB' $attacker.Credential $probe @('rewrite', $admissionDb, $outsideFile)
    Require-UserDenial 'ATTACKER_APPEND_ADMISSION_DB' $attacker.Credential $probe @('append', $admissionDb, $outsideFile)
    Require-UserDenial 'ATTACKER_RENAME_ADMISSION_DB' $attacker.Credential $probe @('rename', $admissionDb, $outsideFile)
    if ((Get-FileHash -LiteralPath $admissionDb -Algorithm SHA256).Hash -ne $admissionHash -or
        (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($admissionDb, 'renamed')))) {
        throw 'E_STORAGE_ADMISSION_DB_CHANGED'
    }
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
    # Delete only the known positive-control artifact; the hostile probe
    # must attempt creation of a verified-absent name, not overwrite.
    $serviceCreated = Join-Path $volume 'forged.sqlite3'
    Require-UserSuccess 'SERVICE_CONTROL_REMOVE_CREATED' $service.Credential $probe @('unlink', $serviceCreated, $serviceFile)
    if (Test-Path -LiteralPath $serviceCreated) { throw 'E_STORAGE_SERVICE_CREATE_CONTROL_NOT_REMOVED' }
    $serviceBefore = (Get-FileHash -LiteralPath $serviceFile -Algorithm SHA256).Hash

    $adminLocalLink = Join-Path $volume 'admin-positive.bin'
    $adminPositive = Start-Process -FilePath $probe -ArgumentList @('hardlink', $serviceFile, $adminLocalLink) -WorkingDirectory $root -PassThru
    Wait-FixtureProcess $adminPositive
    if ($adminPositive.ExitCode -ne 0) { throw 'E_STORAGE_ADMIN_LOCAL_HARDLINK_FAILED' }
    # Keep a kernel-identical, separately named administrator witness until
    # AFTER all malicious operations. Equal final bytes alone cannot detect
    # an inode/file-ID substitution.
    $beforeIdentity = Start-Process -FilePath $probe -ArgumentList @('same-object', $serviceFile, $adminLocalLink) -WorkingDirectory $root -PassThru
    Wait-FixtureProcess $beforeIdentity
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
    if (Test-Path -LiteralPath $serviceCreated) { throw 'E_STORAGE_ATTACK_CREATE_NAME_NOT_ABSENT' }
    Require-UserDenial 'ATTACKER_CANNOT_CREATE_SERVICE' $attacker.Credential $probe @('create', $serviceFile, $outsideFile)
    if (Test-Path -LiteralPath $serviceCreated) { throw 'E_STORAGE_ATTACK_CREATE_OBJECT_EXISTS' }
    if ((Get-FileHash -LiteralPath $serviceFile -Algorithm SHA256).Hash -ne $serviceBefore -or
        (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($serviceFile, '.renamed')))) {
        throw 'E_STORAGE_PROTECTED_OBJECT_CHANGED'
    }
    $afterIdentity = Start-Process -FilePath $probe -ArgumentList @('same-object', $serviceFile, $adminLocalLink) -WorkingDirectory $root -PassThru
    Wait-FixtureProcess $afterIdentity
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
    # A fixed, service-owned NTFS object on the separate VHD: not a client
    # pathname, not a user-owned root and not a production broker policy.
    $nativeReadFile = Join-Path $volume 'service-read.bin'
    $nativeReadBytes = [Text.Encoding]::ASCII.GetBytes('JDC_T011_BOUND_READ_BYTES')
    [System.IO.File]::WriteAllBytes($nativeReadFile, $nativeReadBytes)
    $nativeReadBefore = (Get-FileHash -LiteralPath $nativeReadFile -Algorithm SHA256).Hash
    Require-UserSuccess 'SERVICE_CAN_READ_NATIVE_READ_FILE' $service.Credential $probe @('read', $nativeReadFile, $nativeReadFile)
    Require-UserDenial 'CLIENT_CANNOT_READ_NATIVE_READ_FILE' $client.Credential $probe @('read', $nativeReadFile, $nativeReadFile)
    Require-UserDenial 'ATTACKER_CANNOT_READ_NATIVE_READ_FILE' $attacker.Credential $probe @('read', $nativeReadFile, $nativeReadFile)
    # Non-shipping named-pipe proof: three different real Windows token SIDs.
    $peerSource = Join-Path (Get-Location).Path 'native/authority-service/target/debug/examples/windows_named_pipe_peer_proof.exe'
    if (-not (Test-Path -LiteralPath $peerSource -PathType Leaf)) { throw 'E_PIPE_PROOF_BINARY_MISSING' }
    $peer = Join-Path $bin 'windows_named_pipe_peer_proof.exe'
    Copy-Item -LiteralPath $peerSource -Destination $peer -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $peerSource -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $peer -Algorithm SHA256).Hash) {
        throw 'E_PIPE_PROOF_BINARY_MISMATCH'
    }
    $pipeName = "\\.\pipe\JDC-T011-$guid"
    $peerLog = Join-Path $env:RUNNER_TEMP "JDC-148-$guid-server.stderr"
    $peerReadyPath = Join-Path $readyDir 'pipe-ready'
    if (Test-Path -LiteralPath $peerReadyPath) { throw 'E_PIPE_READY_STALE' }
    # Register before launch; WaitNamedPipeW cannot wait for a missing instance.
    # A .NET filesystem event replaces startup sleeps and retry loops.
    $peerReadyWatcher = [System.IO.FileSystemWatcher]::new($readyDir, 'pipe-ready')
    $peerReadyWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName
    $peerReadyWatcher.EnableRaisingEvents = $true
    Register-ObjectEvent -InputObject $peerReadyWatcher -EventName Created -SourceIdentifier $peerReadySourceId | Out-Null
    $peerServer = Start-Process -FilePath $peer -Credential $service.Credential -ArgumentList @(
        'serve', $pipeName, $service.SID.Value, $client.SID.Value,
        $attacker.SID.Value, $peerReadyPath, $volume
    ) -WorkingDirectory $root -PassThru -RedirectStandardError $peerLog
    if (-not (Test-Path -LiteralPath $peerReadyPath -PathType Leaf)) {
        $readyEvent = Wait-Event -SourceIdentifier $peerReadySourceId -Timeout 12
        if ($null -eq $readyEvent) {
            $errors = @(Get-Content -LiteralPath $peerLog -ErrorAction SilentlyContinue |
                Where-Object { $_ -cmatch '^E_PIPE_[A-Z0-9_]+$' })
            $reason = if ($errors.Count -eq 1) { $errors[0] } else { 'NO_SAFE_DIAGNOSTIC' }
            throw "E_PIPE_LISTENER_READY_TIMEOUT_$reason"
        }
    }
    if (-not (Test-Path -LiteralPath $peerReadyPath -PathType Leaf)) {
        throw 'E_PIPE_LISTENER_READY_NOT_CONFIRMED'
    }
    # Real Windows kernel DACL rejection, not merely application-level denial.
    # The fixture client explicitly requires ERROR_ACCESS_DENIED, not timeout,
    # FILE_NOT_FOUND or a synthetic denial byte from a reachable server.
    Invoke-PeerClient $attacker.Credential $peer 'deny' $pipeName 'T011_WINDOWS_UNTRUSTED_CLIENT_NO_GRANT'
    Write-Output 'T011_WINDOWS_FOREIGN_SID_DENIED_BY_KERNEL'
    Invoke-PeerClient $client.Credential $peer 'allow' $pipeName 'T011_WINDOWS_LEGITIMATE_CLIENT_SID_OBSERVED'
    if (-not $peerServer.WaitForExit(12000)) { throw 'E_PIPE_PROOF_SERVER_TIMEOUT' }
    if ($peerServer.ExitCode -ne 0) { throw 'E_PIPE_PROOF_SERVER_FAILED' }
    if (-not (Select-String -LiteralPath $peerLog -SimpleMatch 'T011_WINDOWS_SEPARATE_SID_PIPE_ACCEPTED_NONRELEASE' -Quiet) -or
        -not (Select-String -LiteralPath $peerLog -SimpleMatch 'T011_WINDOWS_PEER_BOUND_SYNTHETIC_READ_PASS_NONRELEASE' -Quiet)) {
        throw 'E_PIPE_PROOF_MISSING_KERNEL_VERDICT'
    }
    Write-Output 'T011_WINDOWS_SEPARATE_SID_PIPE_ACCEPTED_NONRELEASE'
    Write-Output 'T011_WINDOWS_PEER_BOUND_SYNTHETIC_READ_PASS_NONRELEASE'
    if ((Get-FileHash -LiteralPath $nativeReadFile -Algorithm SHA256).Hash -ne $nativeReadBefore) {
        throw 'E_PIPE_FIXED_PROOF_OBJECT_CHANGED'
    }
    if ((Get-FileHash -LiteralPath $outsideFile -Algorithm SHA256).Hash -ne $before) {
        throw 'E_STORAGE_EXTERIOR_BYTES_CHANGED'
    }
    Write-Output 'T011_STORAGE_EXTERIOR_BYTES_UNCHANGED'
    Write-Output 'T011_STORAGE_WINDOWS_DOMAIN_PASS_NONRELEASE'

    # Separate read-only prerequisite for a future cross-principal SDK
    # launch. It neither assigns privileges nor changes a token/session.
    # The current issuer and the three dedicated principals are observed
    # by the same hashed native binary from the administrator-owned root.
    $principalInput = Join-Path $root 'fixture-principal-input.txt'
    if (Test-Path -LiteralPath $principalInput) { throw 'E_STORAGE_PRINCIPAL_INPUT_PREEXISTS' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $issuerSid = $identity.User.Value
        $issuerSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        [System.IO.File]::WriteAllLines($principalInput, [string[]]@(
            $issuerSession.ToString([Globalization.CultureInfo]::InvariantCulture),
            $issuerSid, $service.SID.Value, $client.SID.Value, $attacker.SID.Value))
    } finally { $identity.Dispose() }
    Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_principal_matches_expected_role' 'T011_WINDOWS_FIXTURE_SERVICE_TOKEN_PASS_NONRELEASE' $service.Credential
    Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_principal_matches_expected_role' 'T011_WINDOWS_FIXTURE_CLIENT_TOKEN_PASS_NONRELEASE' $client.Credential
    Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_principal_matches_expected_role' 'T011_WINDOWS_FIXTURE_ATTACKER_TOKEN_PASS_NONRELEASE' $attacker.Credential
    # Keep the legacy launch preflight executable and fail-closed for its
    # original architecture. The mandatory storage-domain gate instead pairs
    # with the independent SCM job, which exercises actual issuance.
    Write-Output 'T011_WINDOWS_STORAGE_DOMAIN_DEDICATED_TOKENS_PASS_NONRELEASE'
    if (-not $StorageDomainOnly) {
        Invoke-AdmissionProbe 'windows_token::fixture_tests::hosted_fixture_issuer_launch_prerequisites' 'T011_WINDOWS_DISTINCT_ISSUER_PREREQUISITES_PASS_NONRELEASE' $null
    }
} catch {
    $primaryFailure = $_
    $code = $_.Exception.Message
    if ($code -notmatch '^E_[A-Z0-9_]+$') { $code = 'E_STORAGE_UNCLASSIFIED_FAILURE' }
    [Console]::Error.WriteLine("T011_WINDOWS_STORAGE_PRIMARY_FAILURE $code")
} finally {
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $peerReadyWatcher) {
        try {
            Unregister-Event -SourceIdentifier $peerReadySourceId -ErrorAction Stop
            Get-Event -SourceIdentifier $peerReadySourceId -ErrorAction SilentlyContinue |
                Remove-Event -ErrorAction Stop
        } catch { $cleanupErrors.Add('PIPE_READY_EVENT') }
        try { $peerReadyWatcher.Dispose() }
        catch { $cleanupErrors.Add('PIPE_READY_WATCHER') }
    }
    if ($null -ne $peerServer) {
        try {
            if (-not $peerServer.HasExited) {
                $peerServer.Kill()
                if (-not $peerServer.WaitForExit(3000)) { throw 'E_PIPE_SERVER_NOT_STOPPED' }
            }
        } catch {
            $processStateUncertain = $true
            $cleanupErrors.Add('PIPE_SERVER_STOP')
        }
    }
    if ($peerLog -and (Test-Path -LiteralPath $peerLog)) {
        try { Remove-Item -LiteralPath $peerLog -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add('PIPE_LOG_REMOVE') }
    }
    try { Confirm-FixtureProcessesStopped }
    catch { $cleanupErrors.Add('OWNED_PROCESS_STOP_UNVERIFIED') }
    if (-not $processStateUncertain -and $rootOwned -and $admissionAliasAttached) {
        try {
            Remove-AdmissionAlias
        } catch { $cleanupErrors.Add('ADMISSION_ALIAS_REMOVE') }
    }
    if (-not $processStateUncertain -and $rootOwned -and -not $admissionAliasAttached -and (Test-Path -LiteralPath $vhd)) {
        try {
            $remainingImage = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
            if ($remainingImage.Attached) {
                Invoke-DiskPart "select vdisk file=`"$vhd`"`ndetach vdisk`nexit"
            }
            if ((Get-DiskImage -ImagePath $vhd -ErrorAction Stop).Attached) { throw 'E_STORAGE_VHD_STILL_ATTACHED' }
            $vhdDetached = $true
        } catch { $cleanupErrors.Add('VHD_DETACH_UNVERIFIED') }
    } elseif ($rootOwned -and -not $imageTransitionAttempted -and -not $processStateUncertain) {
        $vhdDetached = $true
    } else {
        $cleanupErrors.Add('VHD_STATE_UNVERIFIED')
    }
    try { Confirm-FixtureProcessesStopped }
    catch { $cleanupErrors.Add('OWNED_CLEANUP_PROCESS_STOP_UNVERIFIED') }
    if ($rootOwned -and -not $processStateUncertain -and $vhdDetached -and -not $admissionAliasAttached -and (Test-Path -LiteralPath $vhd)) {
        try { Remove-Item -LiteralPath $vhd -Force -ErrorAction Stop }
        catch {
            $vhdDetached = $false
            $cleanupErrors.Add('VHD_REMOVE')
        }
    }
    if ($rootOwned -and -not $processStateUncertain -and $vhdDetached -and -not $admissionAliasAttached -and (Test-Path -LiteralPath $root)) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch { $cleanupErrors.Add('ROOT_REMOVE') }
    }
    foreach ($name in $createdUsers) {
        if ($processStateUncertain) { $cleanupErrors.Add('ACCOUNT_RETAINED_UNCERTAIN_PROCESS'); continue }
        try { Remove-LocalUser -Name $name -ErrorAction Stop }
        catch { $cleanupErrors.Add('ACCOUNT_REMOVE') }
    }
    if ($cleanupErrors.Count -gt 0) {
        $cleanupCode = "E_STORAGE_CLEANUP_FAILED_$($cleanupErrors -join '_')"
        [Console]::Error.WriteLine($cleanupCode)
        if ($null -eq $primaryFailure) { throw $cleanupCode }
    }
}
if ($null -ne $primaryFailure) { throw $primaryFailure }
