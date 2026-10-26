# T011: actual SCM restricted-principal vs independently administered HKLM epoch.
# Test-only disposable CI fixture. Must never execute on a user's Windows host.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $env:ProgramData) {
    throw 'E_EPOCH_DISPOSABLE_WINDOWS_RUNNER_REQUIRED'
}
$sc = (Get-Command sc.exe -ErrorAction Stop).Source
$service = 'JameDesktopCommanderAuthority'
$registryParent = 'HKLM:\SOFTWARE\JameDesktopCommander'
$registryKey = Join-Path $registryParent 'Authority\EpochAnchor'
if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
    throw 'E_EPOCH_SCM_SERVICE_PREEXISTS'
}
if (Test-Path -LiteralPath $registryParent) {
    throw 'E_EPOCH_REGISTRY_PARENT_PREEXISTS'
}
$stage = Join-Path $env:ProgramData ('JDC-T011-EPOCH-' + [guid]::NewGuid().ToString('N'))
$binary = Join-Path $stage 'windows_epoch_scm_probe.exe'
$built = Join-Path (Get-Location).Path 'native/authority-service/target/debug/examples/windows_epoch_scm_probe.exe'
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) {
    throw 'E_EPOCH_DEBUG_PROBE_MISSING'
}
$createdService = $false
$createdRegistry = $false
$ba = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$all = [System.Security.AccessControl.RegistryRights]::FullControl
$read = [System.Security.AccessControl.RegistryRights]::ReadKey

function Set-ExactAdminControlledKey([bool] $foreign) {
    $security = [System.Security.AccessControl.RegistrySecurity]::new()
    $security.SetOwner($ba)
    $security.SetAccessRuleProtection($true, $false)
    $rules = @(
        @{ Sid = $system; Rights = $all },
        @{ Sid = $ba; Rights = $all },
        @{ Sid = $virtualSid; Rights = $read }
    )
    if ($foreign) {
        $rules += @{ Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11'); Rights = $read }
    }
    foreach ($item in $rules) {
        $rule = [System.Security.AccessControl.RegistryAccessRule]::new(
            $item.Sid, $item.Rights,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $registryKey -AclObject $security -ErrorAction Stop
    $actual = Get-Acl -LiteralPath $registryKey -ErrorAction Stop
    if (-not $actual.AreAccessRulesProtected -or
        $actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $ba.Value -or
        $actual.Access.Count -ne $rules.Count) {
        throw 'E_EPOCH_ACL_FIXTURE_INVALID'
    }
    foreach ($ace in $actual.Access) {
        if ($ace.IsInherited -or $ace.AccessControlType -ne 'Allow') {
            throw 'E_EPOCH_ACL_NOT_EXPLICIT_ALLOW'
        }
    }
}

function Expect-ScmResult([string] $scenario, [int] $expected) {
    & $sc start $service | Out-Null
    $controller = Get-Service -Name $service -ErrorAction Stop
    $controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [timespan]::FromSeconds(15))
    $observed = Get-CimInstance Win32_Service -Filter "Name='$service'"
    if ($null -eq $observed -or $observed.State -ne 'Stopped' -or
        $observed.ExitCode -ne 1066 -or
        $observed.ServiceSpecificExitCode -ne $expected -or
        $observed.ProcessId -ne 0) {
        throw "E_EPOCH_UNEXPECTED_SCM_EXIT_$scenario (expected=$expected)"
    }
}

try {
    New-Item -Path $stage -ItemType Directory -ErrorAction Stop | Out-Null
    & $sc create $service 'type=' 'own' 'start=' 'demand' 'binPath=' $binary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_EPOCH_SCM_CREATE_FAILED' }
    $createdService = $true
    & $sc config $service 'obj=' "NT SERVICE\$service" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_EPOCH_SCM_IDENTITY_CONFIG_FAILED' }
    & $sc sidtype $service restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_EPOCH_SCM_RESTRICTED_SID_FAILED' }
    $sddl = (Get-Content -LiteralPath 'packaging/experimental/windows/jdc-authority-service.sddl' -Raw).Trim()
    & $sc sdset $service $sddl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_EPOCH_SCM_SDSET_FAILED' }
    $virtualSid = ([System.Security.Principal.NTAccount]::new("NT SERVICE\$service")).Translate(
        [System.Security.Principal.SecurityIdentifier])

    # Service may read executable only; admin owns the staging root.
    $stageAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $stageAcl.SetOwner($ba)
    $stageAcl.SetAccessRuleProtection($true, $false)
    foreach ($item in @(
        @{ Sid=$system; Rights=[System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid=$ba; Rights=[System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid=$virtualSid; Rights=[System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $item.Sid, $item.Rights,
            ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $stageAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $stage -AclObject $stageAcl -ErrorAction Stop
    Copy-Item -LiteralPath $built -Destination $binary -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) {
        throw 'E_EPOCH_PROBE_BINARY_PROVENANCE_MISMATCH'
    }

    New-Item -Path $registryParent -ItemType Key -ErrorAction Stop | Out-Null
    $createdRegistry = $true
    New-Item -Path (Join-Path $registryParent 'Authority') -ItemType Key -ErrorAction Stop | Out-Null
    New-Item -Path $registryKey -ItemType Key -ErrorAction Stop | Out-Null
    # V1 is ONE atomic REG_BINARY value: 8-byte BE epoch + 32-byte digest.
    $anchor = [byte[]]::new(40)
    $anchor[7] = 7
    for ($i = 8; $i -lt 40; $i++) { $anchor[$i] = 0xA5 }
    New-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -PropertyType Binary -Value $anchor -ErrorAction Stop | Out-Null
    Set-ExactAdminControlledKey $false

    Expect-ScmResult 'EXACT_PROTECTED_POLICY_ANCHOR' 51
    $anchor[7] = 8
    Set-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -Value $anchor -ErrorAction Stop
    Expect-ScmResult 'AHEAD_OF_SNAPSHOT' 52
    $anchor[7] = 7
    Set-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -Value $anchor -ErrorAction Stop
    Expect-ScmResult 'RESTORED_POLICY_ANCHOR' 51
    Remove-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -ErrorAction Stop
    Expect-ScmResult 'MISSING_ANCHOR' 52
    New-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -PropertyType Binary -Value $anchor -ErrorAction Stop | Out-Null
    $anchor[8] = 0xA6
    Set-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -Value $anchor -ErrorAction Stop
    Expect-ScmResult 'SAME_EPOCH_DIFFERENT_POLICY_DIGEST' 52
    $anchor[8] = 0xA5
    Set-ItemProperty -LiteralPath $registryKey -Name PolicyAnchorV1 -Value $anchor -ErrorAction Stop
    Expect-ScmResult 'RESTORED_POLICY_DIGEST' 51
    Set-ExactAdminControlledKey $true
    Expect-ScmResult 'FOREIGN_ACL_TRUSTEE' 52
    Write-Output 'T011 Windows actual SCM independently protected registry epoch: PASS (non-release)'
}
finally {
    $cleanupFailed = $false
    if ($createdService) {
        & $sc delete $service | Out-Null
        if ($LASTEXITCODE -ne 0) { $cleanupFailed = $true }
    }
    if ($createdRegistry) {
        try { Remove-Item -LiteralPath $registryParent -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailed = $true }
    }
    if (Test-Path -LiteralPath $stage) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailed = $true }
    }
    if ($cleanupFailed) { throw 'E_EPOCH_DISPOSABLE_RESOURCE_CLEANUP_FAILED' }
}
