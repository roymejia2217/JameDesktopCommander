# Snapshot Windows Registry values without reading private data into logs.
# The digest distinguishes registry types, scalar/array boundaries, and bytes.
# This is test evidence, not proof that any particular process caused drift.
function Get-RegistrySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$keys)

    $snapshot = foreach ($key in $keys) {
        if (!(Test-Path -LiteralPath $key -ErrorAction Stop)) {
            "$key|absent"
            continue
        }

        $registry = Get-Item -LiteralPath $key -ErrorAction Stop
        try {
            $names = [string[]]@($registry.GetValueNames())
            [Array]::Sort($names, [StringComparer]::Ordinal)
            $fields = foreach ($name in $names) {
                # Preserve REG_EXPAND_SZ as stored, not the caller's environment.
                $value = $registry.GetValue(
                    $name, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $record = [ordered]@{
                    name = $name
                    kind = [string]$registry.GetValueKind($name)
                    value = $value
                }
                ConvertTo-Json -InputObject $record -Compress -Depth 16
            }
            # A hash, not a value/command-line, is retained by the caller.
            $payload = (@($fields) -join [char]10)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))
                $hex = ([BitConverter]::ToString($digest)).Replace('-', '')
            } finally {
                $sha.Dispose()
            }
            "$key|present|$hex"
        } finally {
            $registry.Close()
        }
    }
    return ($snapshot -join [char]10)
}
