# C4m: CI-only SCM acceptance. Not a production installer.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $env:ProgramData) {
    throw 'E_SCM_EPHEMERAL_WINDOWS_RUNNER_REQUIRED'
}
$serviceName = 'JameDesktopCommanderAuthority'
$virtualAccount = "NT SERVICE\$serviceName"
$sc = (Get-Command sc.exe -ErrorAction Stop).Source
$stage = Join-Path $env:ProgramData ('JDC-T011-SCM-' + [guid]::NewGuid().ToString('N'))
$binary = Join-Path $stage 'jdc-authority-scm.exe'
$built = Join-Path (Get-Location).Path 'native/authority-service/target/debug/jdc-authority-scm.exe'
$created = $false
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { throw 'E_SCM_BINARY_NOT_BUILT' }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'E_SCM_SERVICE_PREEXISTS'
}
function Set-RestrictedAcl([string] $target, [bool] $directory, $virtualSid) {
    $acl = Get-Acl -LiteralPath $target
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    if ($directory) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    foreach ($entry in @(
        @{ Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'); Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = $virtualSid; Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Sid, $entry.Rights,
            $inherit, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.SetAccessRule($rule)
    }
    Set-Acl -LiteralPath $target -AclObject $acl
    if (-not (Get-Acl -LiteralPath $target).AreAccessRulesProtected) {
        throw 'E_SCM_INHERITANCE_NOT_PROTECTED'
    }
}
try {
    New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
    & $sc create $serviceName 'type=' 'own' 'start=' 'demand' 'binPath=' $binary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_CREATE_FAILED' }
    $created = $true
    & $sc config $serviceName 'obj=' $virtualAccount | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_VIRTUAL_ACCOUNT_CONFIG_FAILED' }
    & $sc sidtype $serviceName restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_RESTRICTED_SID_CONFIG_FAILED' }
    $virtualSid = ([System.Security.Principal.NTAccount]::new($virtualAccount)).Translate(
        [System.Security.Principal.SecurityIdentifier])
    Set-RestrictedAcl $stage $true $virtualSid
    Copy-Item -LiteralPath $built -Destination $binary -ErrorAction Stop
    Set-RestrictedAcl $binary $false $virtualSid
    if ((Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) {
        throw 'E_SCM_BINARY_PROVENANCE_MISMATCH'
    }

    $config = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $config -or $config.StartName -ne $virtualAccount -or
        $config.StartMode -ne 'Manual' -or $config.ServiceType -ne 'Own Process') {
        throw 'E_SCM_SERVICE_IDENTITY_OR_CONFIG_MISMATCH'
    }
    # The standalone executable MUST NOT function as an interactive helper.
    $direct = Start-Process -FilePath $binary -PassThru -Wait -ErrorAction Stop
    if ($direct.ExitCode -eq 0) { throw 'E_SCM_INTERACTIVE_LAUNCH_ACCEPTED' }

    # sc.exe may return success or failure as the service transitions rapidly;
    # neither return value proves correctness. Inspect the *final SCM state*.
    & $sc start $serviceName | Out-Null
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [timespan]::FromSeconds(15))
    $state = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $state -or $state.State -ne 'Stopped' -or
        $state.ExitCode -ne 1066 -or $state.ServiceSpecificExitCode -ne 1) {
        throw 'E_SCM_WRONG_DENIAL_REASON'
    }
    if ($state.ProcessId -ne 0) { throw 'E_SCM_PROCESS_STILL_RUNNING' }
    Write-Output 'T011-C4m Windows SCM virtual-account denial: PASS (non-release)'
}
finally {
    $cleanupFailure = $false
    if ($created) {
        & $sc delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { $cleanupFailure = $true }
    }
    if (Test-Path -LiteralPath $stage) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailure = $true }
    }
    if ($cleanupFailure) { throw 'E_SCM_EPHEMERAL_CLEANUP_FAILED' }
}
