# Isolated, real Windows registry acceptance for immutable installer-state evidence.
# Mutates only a random HKCU:\Software test key, never actual startup keys.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../scripts/windows-registry-snapshot.ps1')

function Assert-Different([string]$before, [string]$after, [string]$caseName) {
    if ($before -ceq $after) { throw "Registry snapshot failed to detect: $caseName" }
}
function Assert-Same([string]$before, [string]$after, [string]$caseName) {
    if ($before -cne $after) { throw "Registry snapshot unstable for: $caseName" }
}
$key = Join-Path 'HKCU:\Software' ('JDC-Registry-Snapshot-TEST-' + [guid]::NewGuid().ToString('N'))
$sentinel = 'SENSITIVE_SNAPSHOT_VALUE_DO_NOT_EMIT'
try {
    $absent = Get-RegistrySnapshot @($key)
    New-Item -Path $key -Force | Out-Null
    $empty = Get-RegistrySnapshot @($key)
    Assert-Different $absent $empty 'missing key vs empty key'

    New-ItemProperty -LiteralPath $key -Name 'entry' -PropertyType MultiString -Value @('alpha','beta') -Force | Out-Null
    $multi = Get-RegistrySnapshot @($key)
    Assert-Same $multi (Get-RegistrySnapshot @($key)) 'same multi-string state'

    New-ItemProperty -LiteralPath $key -Name 'entry' -PropertyType String -Value 'alpha beta' -Force | Out-Null
    $single = Get-RegistrySnapshot @($key)
    Assert-Different $multi $single 'REG_MULTI_SZ vs REG_SZ with identical legacy text'

    New-ItemProperty -LiteralPath $key -Name 'entry' -PropertyType String -Value $sentinel -Force | Out-Null
    $sensitive = Get-RegistrySnapshot @($key)
    Assert-Different $single $sensitive 'changed value'
    if ($sensitive.Contains($sentinel)) { throw 'Registry snapshot disclosed sensitive value' }

    New-ItemProperty -LiteralPath $key -Name 'other' -PropertyType DWord -Value 21 -Force | Out-Null
    $added = Get-RegistrySnapshot @($key)
    Assert-Different $sensitive $added 'added registry value'

    Remove-ItemProperty -LiteralPath $key -Name 'other'
    Assert-Same $sensitive (Get-RegistrySnapshot @($key)) 'removed value restores snapshot'

    New-ItemProperty -LiteralPath $key -Name 'other' -PropertyType Binary -Value ([byte[]](0,1,2,3)) -Force | Out-Null
    $binary = Get-RegistrySnapshot @($key)
    New-ItemProperty -LiteralPath $key -Name 'other' -PropertyType Binary -Value ([byte[]](0,1,2,4)) -Force | Out-Null
    Assert-Different $binary (Get-RegistrySnapshot @($key)) 'changed REG_BINARY bytes'

    New-ItemProperty -LiteralPath $key -Name 'other' -PropertyType DWord -Value 21 -Force | Out-Null
    $dword = Get-RegistrySnapshot @($key)
    New-ItemProperty -LiteralPath $key -Name 'other' -PropertyType QWord -Value ([long]21) -Force | Out-Null
    Assert-Different $dword (Get-RegistrySnapshot @($key)) 'REG_DWORD vs REG_QWORD'

    $envName = 'JDC_REGISTRY_SNAPSHOT_TEST_VAR'
    $prior = [Environment]::GetEnvironmentVariable($envName, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($envName, 'first', 'Process')
        New-ItemProperty -LiteralPath $key -Name 'expand' -PropertyType ExpandString -Value '%JDC_REGISTRY_SNAPSHOT_TEST_VAR%' -Force | Out-Null
        $expandedBefore = Get-RegistrySnapshot @($key)
        [Environment]::SetEnvironmentVariable($envName, 'second', 'Process')
        Assert-Same $expandedBefore (Get-RegistrySnapshot @($key)) 'REG_EXPAND_SZ independent of process env'
    } finally {
        [Environment]::SetEnvironmentVariable($envName, $prior, 'Process')
    }

    Write-Output 'WINDOWS_REGISTRY_TYPE_AND_CONTENT_SNAPSHOT_TEST=PASS'
} finally {
    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
}
