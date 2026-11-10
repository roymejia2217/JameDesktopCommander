# Real-registry, privacy-preserving diagnostics acceptance. Never touches Run keys.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../scripts/windows-registry-snapshot.ps1')

function Assert-Delta([object]$before, [object]$after, [string]$expected, [string]$caseName) {
    $delta = Get-RegistryChangeSummary -Before $before -After $after
    if ($delta -cne $expected) {
        throw "Wrong registry-drift classification: $caseName"
    }
    if ($delta.Contains('PRIVATE_NAME') -or $delta.Contains('PRIVATE_VALUE')) {
        throw "Private registry value leaked in drift summary: $caseName"
    }
}
$key = Join-Path 'HKCU:\Software' ('JDC-Registry-Delta-TEST-' + [guid]::NewGuid().ToString('N'))
$zero = 'presenceChanged=false;added=0;removed=0;typeChanged=0;dataChanged=0'
try {
    $missing = Get-RegistrySnapshotDetail -Key $key
    New-Item -Path $key -Force | Out-Null
    $empty = Get-RegistrySnapshotDetail -Key $key
    Assert-Delta $missing $empty 'presenceChanged=true;added=0;removed=0;typeChanged=0;dataChanged=0' 'missing to empty'
    Assert-Delta $empty $empty $zero 'unchanged empty'

    New-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME' -PropertyType MultiString -Value @('alpha','beta') -Force | Out-Null
    $multi = Get-RegistrySnapshotDetail -Key $key
    Assert-Delta $empty $multi 'presenceChanged=false;added=1;removed=0;typeChanged=0;dataChanged=0' 'add one'
    Assert-Delta $multi (Get-RegistrySnapshotDetail -Key $key) $zero 'unchanged multi'

    New-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME' -PropertyType String -Value 'alpha beta' -Force | Out-Null
    $scalar = Get-RegistrySnapshotDetail -Key $key
    Assert-Delta $multi $scalar 'presenceChanged=false;added=0;removed=0;typeChanged=1;dataChanged=0' 'multistring to scalar'

    New-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME' -PropertyType String -Value 'PRIVATE_VALUE_DO_NOT_EMIT' -Force | Out-Null
    $secret = Get-RegistrySnapshotDetail -Key $key
    Assert-Delta $scalar $secret 'presenceChanged=false;added=0;removed=0;typeChanged=0;dataChanged=1' 'changed secret content'
    if ($secret.Snapshot.Contains('PRIVATE_VALUE_DO_NOT_EMIT')) { throw 'Digest disclosed private content' }

    Remove-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME'
    $removed = Get-RegistrySnapshotDetail -Key $key
    Assert-Delta $secret $removed 'presenceChanged=false;added=0;removed=1;typeChanged=0;dataChanged=0' 'removed value'

    New-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME' -PropertyType Binary -Value ([byte[]](0,1,2,3)) -Force | Out-Null
    $binary = Get-RegistrySnapshotDetail -Key $key
    New-ItemProperty -LiteralPath $key -Name 'PRIVATE_NAME' -PropertyType Binary -Value ([byte[]](0,1,2,4)) -Force | Out-Null
    Assert-Delta $binary (Get-RegistrySnapshotDetail -Key $key) 'presenceChanged=false;added=0;removed=0;typeChanged=0;dataChanged=1' 'binary bytes'

    # The original key-wide digest contract must remain byte/type aware.
    if ((Get-RegistrySnapshot @($key)) -cne (Get-RegistrySnapshotDetail -Key $key).Snapshot) {
        throw 'Existing snapshot contract diverged from diagnostic evidence'
    }
    Write-Output 'WINDOWS_REGISTRY_DRIFT_CLASSIFICATION_TEST=PASS'
} finally {
    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
}
