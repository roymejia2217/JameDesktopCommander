# T011-C4i-b: disposable GitHub-hosted Windows NTFS custody acceptance.
# NEVER run on the installed user host or treat as a service installer.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'E_CUSTODY_EPHEMERAL_WINDOWS_RUNNER_REQUIRED'
}
if (-not $env:RUNNER_TEMP -or -not $env:ProgramData) {
    throw 'E_CUSTODY_MISSING_RUNNER_DIRECTORIES'
}
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
$serviceName = 'jdc-ci-svc'
$attackerName = 'jdc-ci-att'
if (Get-LocalUser -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'E_CUSTODY_EXISTING_SERVICE_TEST_ACCOUNT'
}
if (Get-LocalUser -Name $attackerName -ErrorAction SilentlyContinue) {
    throw 'E_CUSTODY_EXISTING_ATTACKER_TEST_ACCOUNT'
}
$createdUsers = [System.Collections.Generic.List[string]]::new()
$testRoot = Join-Path $env:ProgramData ('JDC-T011-C4IB-' + [guid]::NewGuid().ToString('N'))

function Create-IsolatedAccount([string] $name) {
    # Password exists only in this runner process memory, never in CI output.
    $randomPassword = 'Aa1!' + [Convert]::ToBase64String(
        [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $secret = ConvertTo-SecureString -String $randomPassword -AsPlainText -Force
    $account = New-LocalUser -Name $name -Password $secret -PasswordNeverExpires -UserMayNotChangePassword -Description 'Ephemeral JDC C4i-b acceptance'
    $script:createdUsers.Add($name)
    $credential = [pscredential]::new("$env:COMPUTERNAME\$name", $secret)
    return [pscustomobject]@{ User = $account; Credential = $credential }
}

function Grant-ExplicitAcl([string] $directory, [array] $grants) {
    $security = Get-Acl -LiteralPath $directory
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($grant in $grants) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $grant.Sid, $grant.Rights, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.SetAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $security -ErrorAction Stop
    if (-not (Get-Acl -LiteralPath $directory).AreAccessRulesProtected) {
        throw 'E_CUSTODY_INHERITANCE_NOT_DISABLED'
    }
}

function Invoke-AsUser([pscredential] $identity, [string] $binary, [string[]] $arguments) {
    $process = Start-Process -FilePath $binary -Credential $identity -ArgumentList $arguments -WorkingDirectory $testRoot -PassThru -Wait -ErrorAction Stop
    if ($null -eq $process.ExitCode) {
        throw 'E_CUSTODY_MISSING_CHILD_EXIT_CODE'
    }
    return [int] $process.ExitCode
}
function Require-Success([string] $label, [pscredential] $identity, [string] $binary, [string[]] $arguments) {
    if ((Invoke-AsUser $identity $binary $arguments) -ne 0) {
        throw "E_CUSTODY_POSITIVE_PROOF_FAILED_$label"
    }
}
function Require-Denied([string] $label, [pscredential] $identity, [string] $binary, [string[]] $arguments) {
    if ((Invoke-AsUser $identity $binary $arguments) -eq 0) {
        throw "E_CUSTODY_UNAUTHORIZED_OPERATION_$label"
    }
}

try {
    $service = Create-IsolatedAccount $serviceName
    $attacker = Create-IsolatedAccount $attackerName
    if ($service.User.SID.Value -eq $attacker.User.SID.Value) {
        throw 'E_CUSTODY_IDENTICAL_SIDS'
    }
    $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $administrators = @(Get-LocalGroupMember -SID $adminSid -ErrorAction Stop)
    foreach ($principal in @($service, $attacker)) {
        if ($administrators.SID.Value -contains $principal.User.SID.Value) {
            throw 'E_CUSTODY_TEST_PRINCIPAL_IS_ADMINISTRATOR'
        }
    }
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $modify = [System.Security.AccessControl.FileSystemRights]::Modify
    $readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $privileged = @(
        @{ Sid = $adminSid; Rights = $full }
        @{ Sid = $systemSid; Rights = $full }
    )

    New-Item -Path $testRoot -ItemType Directory -ErrorAction Stop | Out-Null
    $state = Join-Path $testRoot 'state'
    $stage = Join-Path $testRoot 'bin'
    $public = Join-Path $testRoot 'attacker-owned'
    foreach ($directory in @($state, $stage, $public)) {
        New-Item -Path $directory -ItemType Directory -ErrorAction Stop | Out-Null
    }
    Grant-ExplicitAcl $testRoot ($privileged + @(
        @{ Sid = $service.User.SID; Rights = $readExecute }
        @{ Sid = $attacker.User.SID; Rights = $readExecute }
    ))
    Grant-ExplicitAcl $stage ($privileged + @(
        @{ Sid = $service.User.SID; Rights = $readExecute }
        @{ Sid = $attacker.User.SID; Rights = $readExecute }
    ))
    Grant-ExplicitAcl $state ($privileged + @(
        @{ Sid = $service.User.SID; Rights = $modify }
    ))
    Grant-ExplicitAcl $public ($privileged + @(
        @{ Sid = $attacker.User.SID; Rights = $full }
    ))

    $source = Join-Path (Get-Location).Path 'native/authority-store/target/debug/examples'
    $fixture = Join-Path $stage 'custody_fixture.exe'
    $probe = Join-Path $stage 'custody_attacker.exe'
    Copy-Item -LiteralPath (Join-Path $source 'custody_fixture.exe') -Destination $fixture -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $source 'custody_attacker.exe') -Destination $probe -ErrorAction Stop
    $db = Join-Path $state 'policy.sqlite3'
    $snapshot = Join-Path $public 'epoch-one.sqlite3'
    $canary = Join-Path $public 'writable-canary.txt'

    # Both distinct SIDs must execute successful operations under their credentials.
    Require-Success 'OWNER_INIT' $service.Credential $fixture @('init', $db)
    Copy-Item -LiteralPath $db -Destination $snapshot -ErrorAction Stop
    Require-Success 'ATTACKER_CANARY' $attacker.Credential $probe @('canary', $db, $canary)
    $attackerOwnedAlias = Join-Path $public 'own-hardlink-canary.txt'
    Require-Success 'ATTACKER_HARDLINK_OWN' $attacker.Credential $probe @('hardlink', $canary, $attackerOwnedAlias)
    if (-not (Test-Path -LiteralPath $attackerOwnedAlias -PathType Leaf)) {
        throw 'E_CUSTODY_POSITIVE_HARDLINK_MISSING'
    }
    if ((Get-FileHash -LiteralPath $attackerOwnedAlias -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $canary -Algorithm SHA256).Hash) {
        throw 'E_CUSTODY_POSITIVE_HARDLINK_BYTES_MISMATCH'
    }
    Require-Success 'ATTACKER_READS_OLD_SNAPSHOT' $attacker.Credential $probe @('read', $snapshot, $canary)
    if (-not (Test-Path -LiteralPath $canary -PathType Leaf)) {
        throw 'E_CUSTODY_MISSING_ATTACKER_CANARY'
    }
    # Prove each adverse file operation works where the attacker owns the ACL.
    Require-Success 'ATTACKER_APPEND_OWN' $attacker.Credential $probe @('append', $canary, $snapshot)
    Require-Success 'ATTACKER_OVERWRITE_OWN' $attacker.Credential $probe @('overwrite', $canary, $snapshot)
    Require-Success 'ATTACKER_RENAME_OWN' $attacker.Credential $probe @('rename', $canary, $snapshot)
    Require-Success 'ATTACKER_CREATE_OWN' $attacker.Credential $probe @('create', $canary, $snapshot)
    Require-Success 'ATTACKER_RECREATE_CANARY' $attacker.Credential $probe @('canary', $canary, $canary)
    Require-Success 'ATTACKER_DELETE_OWN' $attacker.Credential $probe @('unlink', $canary, $snapshot)
    $nested = Join-Path $public 'nested'
    New-Item -Path $nested -ItemType Directory -ErrorAction Stop | Out-Null
    Require-Success 'ATTACKER_RENAME_OWN_PARENT' $attacker.Credential $probe @('parent-rename', (Join-Path $nested 'unused.sqlite3'), $snapshot)
    $icacls = (Get-Command icacls.exe -ErrorAction Stop).Source
    $grantTarget = "$env:COMPUTERNAME\" + $attackerName + ':(OI)(CI)F'
    Require-Success 'ATTACKER_CAN_CHANGE_OWN_DACL' $attacker.Credential $icacls @($public, '/grant', $grantTarget)
    Require-Success 'OWNER_ADVANCE' $service.Credential $fixture @('advance', $db)
    Require-Success 'OWNER_READ' $service.Credential $fixture @('verify-2', $db)
    $before = (Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash

    foreach ($operation in @('read', 'append', 'rename', 'unlink', 'create', 'parent-rename')) {
        Require-Denied $operation $attacker.Credential $probe @($operation, $db, $snapshot)
    }
    $exfiltrationAlias = Join-Path $public 'protected-object-hardlink.txt'
    $injectedAlias = Join-Path $state 'attacker-owned-hardlink.txt'
    Require-Denied 'HARDLINK_FROM_PROTECTED' $attacker.Credential $probe @('hardlink', $db, $exfiltrationAlias)
    Require-Denied 'HARDLINK_INTO_PROTECTED' $attacker.Credential $probe @('hardlink', $canary, $injectedAlias)
    if ((Test-Path -LiteralPath $exfiltrationAlias) -or (Test-Path -LiteralPath $injectedAlias)) {
        throw 'E_CUSTODY_HARDLINK_ALIAS_CREATED'
    }
    Require-Denied 'replay' $attacker.Credential $probe @('overwrite', $db, $snapshot)
    # The same validated icacls invocation must now fail on protected state.
    Require-Denied 'CHANGE_DACL' $attacker.Credential $icacls @($state, '/grant', $grantTarget)

    Require-Success 'OWNER_EPOCH_AFTER_ATTACK' $service.Credential $fixture @('verify-2', $db)
    $after = (Get-FileHash -LiteralPath $db -Algorithm SHA256).Hash
    if ($before -ne $after) {
        throw 'E_CUSTODY_UNAUTHORIZED_DATABASE_BYTES_CHANGED'
    }
    Write-Output 'T011-C4i-b Windows distinct-principal NTFS custody: PASS (non-release)'
}
finally {
    # Cleanup applies exclusively to artifacts created on this disposable runner.
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
    }
    foreach ($accountName in $createdUsers) {
        Remove-LocalUser -Name $accountName -ErrorAction Stop
    }
}
