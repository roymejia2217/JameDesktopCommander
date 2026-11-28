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
$proofBuilt = Join-Path (Get-Location).Path 'native/authority-service/target/debug/jdc-authority-scm-issued-proof.exe'
$clientBuilt = Join-Path (Get-Location).Path 'native/authority-service/target/debug/jdc-authority-scm-issued-client.exe'
$proofBinary = Join-Path $stage 'jdc-authority-scm-issued-proof.exe'
$clientBinary = Join-Path $stage 'jdc-authority-scm-issued-client.exe'
$created = $false
$issuerName = 'JameDesktopCommanderIssuer'
$issuerAccount = "NT SERVICE\$issuerName"
$issuerCreated = $false
if (Get-Service -Name $issuerName -ErrorAction SilentlyContinue) {
    throw 'E_SCM_ISSUER_PREEXISTS'
}
foreach ($file in @($built, $proofBuilt, $clientBuilt)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'E_SCM_BINARY_NOT_BUILT' }
}
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

function Get-ScmDescriptor([string] $name = $serviceName) {
    $result = @(& $sc sdshow $name)
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
# The proof rendezvous is administrator-owned; only the fixed issuer may
# write inside handoff, and the independent authority is a read-only observer.
function Assert-DualRoleAcl([string] $target, $authoritySid, $issuerSid, [System.Security.AccessControl.FileSystemRights] $issuerRights, [bool] $protected) {
    $acl = Get-Acl -LiteralPath $target
    if ($protected -and -not $acl.AreAccessRulesProtected) { throw 'E_SCM_HANDOFF_ACL_INHERITED' }
    $sync = [System.Security.AccessControl.FileSystemRights]::Synchronize
    $expected = @{
        'S-1-5-32-544' = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-18' = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        $authoritySid.Value = [int]([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor $sync)
        $issuerSid.Value = [int]($issuerRights -bor $sync)
    }
    $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expected.Count) { throw 'E_SCM_HANDOFF_ACL_UNEXPECTED_GRANT' }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($seen.ContainsKey($sid) -or -not $expected.ContainsKey($sid) -or
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            [int]$rule.FileSystemRights -ne $expected[$sid]) {
            throw 'E_SCM_HANDOFF_ACL_UNEXPECTED_GRANT'
        }
        $seen[$sid] = $true
    }
}
function Set-DualRoleAcl([string] $target, [bool] $directory, $authoritySid, $issuerSid, [System.Security.AccessControl.FileSystemRights] $issuerRights) {
    $acl = Get-Acl -LiteralPath $target
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
        $acl.RemoveAccessRuleSpecific($rule)
    }
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    if ($directory) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    foreach ($entry in @(
        @{ Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'); Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'); Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = $authoritySid; Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute },
        @{ Sid = $issuerSid; Rights = $issuerRights }
    )) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Sid, $entry.Rights, $inherit, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $target -AclObject $acl
    Assert-DualRoleAcl $target $authoritySid $issuerSid $issuerRights $true
}

function Invoke-ScmAsAttacker([pscredential] $identity, [string[]] $arguments) {
    $child = Start-Process -FilePath $sc -Credential $identity -ArgumentList $arguments -WorkingDirectory $env:windir -PassThru -Wait -ErrorAction Stop
    if ($null -eq $child.ExitCode) { throw 'E_SCM_ATTACKER_EXIT_UNAVAILABLE' }
    return [int]$child.ExitCode
}

$primaryFailure = $null
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
    Copy-Item -LiteralPath $proofBuilt -Destination $proofBinary -ErrorAction Stop
    Copy-Item -LiteralPath $clientBuilt -Destination $clientBinary -ErrorAction Stop
    foreach ($installed in @($binary, $proofBinary, $clientBinary)) {
        Set-RestrictedAcl $installed $false $virtualSid
    }
    if ((Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -or
        (Get-FileHash -LiteralPath $proofBuilt -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $proofBinary -Algorithm SHA256).Hash -or
        (Get-FileHash -LiteralPath $clientBuilt -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $clientBinary -Algorithm SHA256).Hash) {
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
    # Interactive launches must fail with the exact dispatcher/identity-denial
    # exit code, not an arbitrary crash or an unavailable exit observation.
    foreach ($fixture in @(
        @{ Image = $binary; ErrorCode = 'E_SCM_INTERACTIVE_LAUNCH_NOT_DENIED' },
        @{ Image = $proofBinary; ErrorCode = 'E_SCM_INTERACTIVE_PROOF_NOT_DENIED' },
        @{ Image = $clientBinary; ErrorCode = 'E_SCM_INTERACTIVE_CHILD_NOT_DENIED' }
    )) {
        $direct = Start-Process -FilePath $fixture.Image -PassThru -Wait -ErrorAction Stop
        if ($null -eq $direct.ExitCode -or [int]$direct.ExitCode -ne 1) {
            throw $fixture.ErrorCode
        }
    }

    # sc.exe may return success or failure as the service transitions rapidly;
    # neither return value proves correctness. Inspect the *final SCM state*.
    & $sc start $serviceName | Out-Null
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [timespan]::FromSeconds(15))
    $state = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $state -or $state.State -ne 'Stopped' -or
        $state.ExitCode -ne 1066) {
        throw 'E_SCM_WRONG_DENIAL_REASON'
    }
    # Codes 2, 4 and 5 are NOT accepted: identity, SID/group boundary and
    # native token-query failures cannot be recorded as an SCM security pass.
    # 3 is fail-closed but means the privilege baseline is STILL unreviewed.
    if ($state.ServiceSpecificExitCode -notin @(1, 3)) {
        throw 'E_SCM_TOKEN_OBSERVATION_INVALID'
    }
    if ($state.ProcessId -ne 0) { throw 'E_SCM_PROCESS_STILL_RUNNING' }
    if ($state.ServiceSpecificExitCode -eq 3) {
        Write-Output 'E_SCM_PRIVILEGE_BASELINE_UNREVIEWED: deny-only, non-release'
    }
    Write-Output 'T011-C4o SCM token audit reached terminal denial: PASS (non-release)'

    # The same real SCM identity now issues a protected child from the
    # administrator-owned staging directory; it never enters RUNNING.
    & $sc config $serviceName 'binPath=' $proofBinary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_PROOF_IMAGE_CONFIGURATION_FAILED' }
    $configured = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $configured -or $configured.PathName -ne $proofBinary) {
        throw 'E_SCM_PROOF_IMAGE_NOT_PINNED'
    }
    & $sc start $serviceName | Out-Null
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $controller.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [timespan]::FromSeconds(15))
    $issuedState = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $issuedState -or $issuedState.State -ne 'Stopped' -or
        $issuedState.ExitCode -ne 1066 -or $issuedState.ServiceSpecificExitCode -ne 6 -or
        $issuedState.ProcessId -ne 0) {
        throw 'E_SCM_REAL_ISSUED_CHILD_PROOF_FAILED'
    }
    if ((Get-ScmDescriptor) -ne $baselineDescriptor) {
        throw 'E_SCM_PROOF_SERVICE_DACL_CHANGED'
    }
    & $sc config $serviceName 'binPath=' $binary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ORIGINAL_IMAGE_RESTORE_FAILED' }
    Write-Output 'T011-C4o SCM-issued protected child: PASS (non-release, no MCP authorization)'

    # Two fixed, separate SCM virtual accounts; no token-launch or debug
    # privileges. The issuer retains its suspended child until the observer
    # has proved limited access and all negative kernel access checks.
    $issuerCommand = '"' + $proofBinary + '" --issuer-observer-proof'
    $observerCommand = '"' + $proofBinary + '" --authority-observer-proof'
    & $sc create $issuerName 'type=' 'own' 'start=' 'demand' 'binPath=' $issuerCommand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_CREATE_FAILED' }
    $issuerCreated = $true
    & $sc config $issuerName 'obj=' $issuerAccount | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_ACCOUNT_FAILED' }
    & $sc sidtype $issuerName restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_RESTRICTED_SID_FAILED' }
    & $sc sdset $issuerName $expectedSddl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_SDSET_FAILED' }
    Assert-ScmDacl (Get-ScmDescriptor $issuerName)
    foreach ($name in @($issuerName, $serviceName)) {
        & $sc privs $name SeChangeNotifyPrivilege | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'E_SCM_FIXTURE_PRIVILEGE_RESTRICTION_FAILED' }
    }
    $issuerSid = ([System.Security.Principal.NTAccount]::new($issuerAccount)).Translate(
        [System.Security.Principal.SecurityIdentifier])
    if ($issuerSid.Value -eq $virtualSid.Value) { throw 'E_SCM_IDENTITIES_NOT_DISTINCT' }
    $rx = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $modify = [System.Security.AccessControl.FileSystemRights]::Modify
    Set-DualRoleAcl $stage $true $virtualSid $issuerSid $rx
    foreach ($installed in @($proofBinary, $clientBinary)) {
        Set-DualRoleAcl $installed $false $virtualSid $issuerSid $rx
    }
    $handoff = Join-Path $stage 'handoff'
    New-Item -ItemType Directory -Path $handoff -ErrorAction Stop | Out-Null
    Set-DualRoleAcl $handoff $true $virtualSid $issuerSid $modify
    & $sc config $serviceName 'binPath=' $observerCommand | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_OBSERVER_IMAGE_CONFIGURATION_FAILED' }
    $issuerConfig = Get-CimInstance Win32_Service -Filter "Name='$issuerName'"
    $observerConfig = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $issuerConfig -or $issuerConfig.StartName -ne $issuerAccount -or
        $issuerConfig.PathName -ne $issuerCommand -or $issuerConfig.StartMode -ne 'Manual' -or
        $issuerConfig.ServiceType -ne 'Own Process' -or
        $null -eq $observerConfig -or $observerConfig.StartName -ne $virtualAccount -or
        $observerConfig.PathName -ne $observerCommand) {
        throw 'E_SCM_DISTINCT_FIXTURE_CONFIG_MISMATCH'
    }
    & $sc start $issuerName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_START_FAILED' }
    $issuerController = Get-Service -Name $issuerName -ErrorAction Stop
    $issuerController.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [timespan]::FromSeconds(15))
    $record = Join-Path $handoff 'issued-process.txt'
    $recordItem = Get-Item -LiteralPath $record -ErrorAction Stop
    if ($recordItem.PSIsContainer -or ($recordItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $recordItem.Length -gt 128 -or (Get-Acl -LiteralPath $record).GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $issuerSid.Value) {
        throw 'E_SCM_HANDOFF_RECORD_CUSTODY'
    }
    Assert-DualRoleAcl $record $virtualSid $issuerSid $modify $false
    & $sc start $serviceName | Out-Null
    $controller = Get-Service -Name $serviceName -ErrorAction Stop
    $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(15))
    $observerState = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $observerState -or $observerState.State -ne 'Stopped' -or
        $observerState.ExitCode -ne 1066 -or $observerState.ServiceSpecificExitCode -ne 8 -or
        $observerState.ProcessId -ne 0) { throw 'E_SCM_DISTINCT_OBSERVER_PROOF_FAILED' }

    # The observer retained the issuer's actual process object through its
    # voluntary exit; issuing a STOP here would mask an incomplete handoff.
    $issuerController.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(15))
    $issuerState = Get-CimInstance Win32_Service -Filter "Name='$issuerName'"
    if ($null -eq $issuerState -or $issuerState.State -ne 'Stopped' -or
        $issuerState.ExitCode -ne 1066 -or $issuerState.ServiceSpecificExitCode -ne 10 -or
        $issuerState.ProcessId -ne 0) { throw 'E_SCM_ISSUER_CLEANUP_FAILED' }
    $jobRecord = Join-Path $handoff 'job-issued-process.txt'
    $jobRecordItem = Get-Item -LiteralPath $jobRecord -ErrorAction Stop
    if ($jobRecordItem.PSIsContainer -or ($jobRecordItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $jobRecordItem.Length -gt 128 -or (Get-Acl -LiteralPath $jobRecord).GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $issuerSid.Value) {
        throw 'E_SCM_JOB_HANDOFF_RECORD_CUSTODY'
    }
    Assert-DualRoleAcl $jobRecord $virtualSid $issuerSid $modify $false
    if ((Get-ScmDescriptor) -ne $baselineDescriptor) { throw 'E_SCM_PROOF_SERVICE_DACL_CHANGED' }
    Assert-ScmDacl (Get-ScmDescriptor $issuerName)
    & $sc config $serviceName 'binPath=' $binary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ORIGINAL_IMAGE_RESTORE_FAILED' }
}
catch {
    $primaryFailure = $_
}
finally {
    $cleanupFailure = $false
    $issuerStopped = $true
    if ($issuerCreated) {
        try {
            $issuerController = Get-Service -Name $issuerName -ErrorAction Stop
            if ($issuerController.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                & $sc stop $issuerName | Out-Null
                $issuerController.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(60))
            }
            $issuerState = Get-CimInstance Win32_Service -Filter "Name='$issuerName'"
            if ($null -eq $issuerState -or $issuerState.State -ne 'Stopped' -or $issuerState.ProcessId -ne 0) {
                throw 'E_SCM_ISSUER_CLEANUP_FAILED'
            }
            & $sc delete $issuerName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'E_SCM_ISSUER_CLEANUP_FAILED' }
        }
        catch { $issuerStopped = $false; $cleanupFailure = $true }
    }
    $authorityStopped = $true
    if ($created) {
        try {
            $controller = Get-Service -Name $serviceName -ErrorAction Stop
            $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(15))
            $state = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            if ($null -eq $state -or $state.State -ne 'Stopped' -or $state.ProcessId -ne 0) {
                throw 'E_SCM_AUTHORITY_CLEANUP_FAILED'
            }
            & $sc delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'E_SCM_AUTHORITY_CLEANUP_FAILED' }
        }
        catch { $authorityStopped = $false; $cleanupFailure = $true }
    }
    if ($issuerStopped -and $authorityStopped -and (Test-Path -LiteralPath $stage)) {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop }
        catch { $cleanupFailure = $true }
    }
    if ($createdAttacker) {
        try { Remove-LocalUser -Name $attackerName -ErrorAction Stop }
        catch { $cleanupFailure = $true }
    }
    if ($cleanupFailure) {
        if ($null -eq $primaryFailure) { throw 'E_SCM_EPHEMERAL_CLEANUP_FAILED' }
        Write-Warning 'E_SCM_EPHEMERAL_CLEANUP_FAILED'
    }
}
if ($null -ne $primaryFailure) { throw $primaryFailure }
Write-Output 'T011_WINDOWS_SCM_DISTINCT_PRINCIPAL_PIN_PASS_NONRELEASE'
Write-Output 'T011_WINDOWS_SCM_JOB_HANDOFF_PASS_NONRELEASE'
