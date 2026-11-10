# Read-only Windows Registry evidence for installer acceptance.
# No value names, command lines, values, or value digests are ever formatted
# into error messages. Deltas describe change classes, NOT the writing process.
function Get-RegistryTextDigest {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Get-RegistrySnapshotDetail {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)

    $entries = [System.Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    if (!(Test-Path -LiteralPath $Key -ErrorAction Stop)) {
        return [pscustomobject]@{
            Snapshot = "$Key|absent"
            Present = $false
            Entries = $entries
        }
    }

    $registry = Get-Item -LiteralPath $Key -ErrorAction Stop
    try {
        $names = [string[]]@($registry.GetValueNames())
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $fields = foreach ($name in $names) {
            # Read the stored data, never process-environment expansions.
            $value = $registry.GetValue(
                $name, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            $kind = [string]$registry.GetValueKind($name)
            $record = [ordered]@{
                name = $name
                kind = $kind
                value = $value
            }
            $serialized = ConvertTo-Json -InputObject $record -Compress -Depth 16
            # Retain only a digest and kind for classification. The value name
            # is kept in memory as a lookup key, never returned to CI logs.
            $entries.Add($name, [pscustomobject]@{
                Kind = $kind
                ContentHash = Get-RegistryTextDigest -Text $serialized
            })
            $serialized
        }
        $payload = (@($fields) -join [char]10)
        return [pscustomobject]@{
            Snapshot = "$Key|present|$(Get-RegistryTextDigest -Text $payload)"
            Present = $true
            Entries = $entries
        }
    } finally {
        $registry.Close()
    }
}

function Get-RegistrySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$keys)

    $snapshot = foreach ($key in $keys) {
        (Get-RegistrySnapshotDetail -Key $key).Snapshot
    }
    return ($snapshot -join [char]10)
}

function Get-RegistryChangeSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Before,
        [Parameter(Mandatory)][object]$After
    )

    $added = 0
    $removed = 0
    $typeChanged = 0
    $dataChanged = 0
    foreach ($name in $After.Entries.Keys) {
        if (!$Before.Entries.ContainsKey($name)) {
            $added++
            continue
        }
        $old = $Before.Entries[$name]
        $new = $After.Entries[$name]
        if ($old.Kind -cne $new.Kind) {
            $typeChanged++
        } elseif ($old.ContentHash -cne $new.ContentHash) {
            $dataChanged++
        }
    }
    foreach ($name in $Before.Entries.Keys) {
        if (!$After.Entries.ContainsKey($name)) { $removed++ }
    }
    $presenceChanged = ($Before.Present -ne $After.Present).ToString().ToLowerInvariant()
    return "presenceChanged=$presenceChanged;added=$added;removed=$removed;typeChanged=$typeChanged;dataChanged=$dataChanged"
}
