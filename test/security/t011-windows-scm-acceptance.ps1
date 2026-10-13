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
$attackerName = 'jdc-ci-scm-att'
$createdAttacker = $false
if (Get-LocalUser -Name $attackerName -ErrorAction SilentlyContinue) {
    throw 'E_SCM_ATTACKER_ACCOUNT_PREEXISTS'
}
$descriptorPath = Join-Path (Get-Location).Path 'packaging/experimental/windows/jdc-authority-service.sddl'
$expectedSddl = (Get-Content -LiteralPath $descriptorPath -Raw -ErrorAction Stop).Trim()

function Get-ScmDescriptor {
    $result = @(& $sc sdshow $serviceName)
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_SDSHOW_FAILED' }
    $sddl = @($result | Where-Object { $_.Trim() -match '^[DOGS]:' } | Select-Object -First 1)
    if ($sddl.Count -ne 1) { throw 'E_SCM_SDDL_MISSING' }
    return $sddl[0].Trim()
}
function Assert-ScmDacl([string] $sddl) {
    $security = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    if (-not ($security.ControlFlags -band
        [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
        throw 'E_SCM_DACL_NOT_PROTECTED'
    }
    $rights = @{
        'S-1-5-18' = 0xF01FF
        'S-1-5-32-544' = 0xF01FF
        'S-1-5-11' = 0x2008D
    }
    if ($null -eq $security.DiscretionaryAcl -or
        $security.DiscretionaryAcl.Count -ne $rights.Count) {
        throw 'E_SCM_ACL_UNEXPECTED_GRANT'
    }
    foreach ($ace in $security.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed -or
            -not $rights.ContainsKey($ace.SecurityIdentifier.Value) -or
            $ace.AccessMask -ne $rights[$ace.SecurityIdentifier.Value] -or
            $ace.AceFlags -ne [System.Security.AccessControl.AceFlags]::None) {
            throw 'E_SCM_ACL_UNEXPECTED_GRANT'
        }
    }
}
function Invoke-ScmAsAttacker([pscredential] $identity, [string[]] $arguments) {
    $child = Start-Process -FilePath $sc -Credential $identity -ArgumentList $arguments -WorkingDirectory $env:windir -PassThru -Wait -ErrorAction Stop
    if ($null -eq $child.ExitCode) { throw 'E_SCM_ATTACKER_EXIT_UNAVAILABLE' }
    return [int]$child.ExitCode
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
    # The experimental service object has a protected, version-controlled
    # DACL. Do not rely on installation-dependent SCM defaults.
    Assert-ScmDacl $expectedSddl
    & $sc sdset $serviceName $expectedSddl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_SDSET_FAILED' }
    $baselineDescriptor = Get-ScmDescriptor
    Assert-ScmDacl $baselineDescriptor
    $virtualSid = ([System.Security.Principal.NTAccount]::new($virtualAccount)).Translate(
        [System.Security.Principal.SecurityIdentifier])
    Set-RestrictedAcl $stage $true $virtualSid
    Copy-Item -LiteralPath $built -Destination $binary -ErrorAction Stop
    Set-RestrictedAcl $binary $false $virtualSid
    if ((Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) {
        throw 'E_SCM_BINARY_PROVENANCE_MISMATCH'
    }

    # A real, separate non-administrator token must prove that safe reads
    # work and privileged SCM operations are denied by the object DACL.
    $secretText = 'Aa1!' + [Convert]::ToBase64String(
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $secret = ConvertTo-SecureString -String $secretText -AsPlainText -Force
    $attackerAccount = New-LocalUser -Name $attackerName -Password $secret -PasswordNeverExpires -UserMayNotChangePassword -Description 'Disposable T011 SCM DACL security acceptance'
    $createdAttacker = $true
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $administrators = @(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop)
    if ($administrators.SID.Value -contains $attackerAccount.SID.Value) {
        throw 'E_SCM_ATTACKER_ADMINISTRATOR'
    }
    $attackerCredential = [pscredential]::new("$env:COMPUTERNAME\$attackerName", $secret)
    foreach ($safe in @(@('query', $serviceName), @('qc', $serviceName))) {
        if ((Invoke-ScmAsAttacker $attackerCredential $safe) -ne 0) {
            throw 'E_SCM_ATTACKER_QUERY_FAILED'
        }
    }
    foreach ($attack in @(
        @('config', $serviceName, 'start=', 'auto'),
        @('start', $serviceName),
        @('stop', $serviceName),
        @('sdset', $serviceName, $expectedSddl),
        @('delete', $serviceName)
    )) {
        # Require the exact Win32 ERROR_ACCESS_DENIED (5); a missing
        # service, malformed arguments or a broken test process is NOT proof.
        if ((Invoke-ScmAsAttacker $attackerCredential $attack) -ne 5) {
            throw 'E_SCM_ATTACKER_MUTATION_SUCCEEDED'
        }
    }
    if ((Get-ScmDescriptor) -ne $baselineDescriptor) {
        throw 'E_SCM_SERVICE_DACL_CHANGED'
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
    if ($createdAttacker) {
        try { Remove-LocalUser -Name $attackerName -ErrorAction Stop }
        catch { $cleanupFailure = $true }
    }
    if ($cleanupFailure) { throw 'E_SCM_EPHEMERAL_CLEANUP_FAILED' }
}
