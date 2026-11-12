# Hosted-only, throwaway Microsoft-signed Sysmon probe. Never run on installed JDC hosts.
param([Parameter(Mandatory)][ValidateSet('Start','Report','Stop')][string]$Mode)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows-sysmon-registry-attribution.ps1')

$expectedBranch = 'diagnostics/issue270-sysmon-runkey-attribution-20261111'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:GITHUB_HEAD_REF -cne $expectedBranch -or
    $env:GITHUB_REPOSITORY -cne 'roymejia2217/JameDesktopCommander' -or !$env:RUNNER_TEMP) {
    throw 'Sysmon diagnostic restricted to its disposable GitHub Windows PR runner'
}
$root = Join-Path $env:RUNNER_TEMP 'jdc-sysmon-attribution'
$stateFile = Join-Path $root 'state.json'
$binary = Join-Path $root 'bin\Sysmon64.exe'
$expectedZip = '00ECF1B46AEC99299D3AE0BCA79DC621458BD014B20B509D7C5C8E8C8611AA54'
$expectedBinary = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'

function Get-SysmonServiceCount {
    return @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue).Count
}
function Get-SourceState {
    if (!(Test-Path -LiteralPath $stateFile -PathType Leaf)) {
        throw 'Owned Sysmon diagnostic state file missing'
    }
    return (Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json)
}
function Write-SourceState([object]$state) {
    ($state | ConvertTo-Json -Compress -Depth 6) |
        Set-Content -LiteralPath $stateFile -Encoding UTF8
}
function Get-Event12Since([datetime]$startedUtc) {
    try {
        return @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            Id = 12
            StartTime = $startedUtc
        } -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return @() }
        throw
    }
}
function Select-ExactRegistryEvidence([AllowEmptyCollection()][object[]]$events, [hashtable]$paths) {
    $result = @()
    foreach ($event in $events) {
        $e = ConvertTo-JdcSysmonRegistryEvidence -XmlText $event.ToXml() -ExactPaths $paths
        if ($e) { $result += $e }
    }
    return $result
}
function Uninstall-OwnedSysmon {
    if (!(Test-Path -LiteralPath $root)) {
        if ((Get-SysmonServiceCount) -gt 0) {
            throw 'Sysmon service exists but no owned state was found; refusing modification'
        }
        Write-Output 'JDC_SYSMON_DIAG_CLEANUP=NOT_NEEDED'
        return
    }
    $state = Get-SourceState
    if (!$state.Owned) { throw 'Sysmon state ownership marker invalid' }
    if ($state.InstallAttempted -or (Get-SysmonServiceCount) -gt 0) {
        if (!(Test-Path -LiteralPath $binary) -or
            (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne $expectedBinary) {
            throw 'Owned Microsoft Sysmon binary missing or invalid; refusing cleanup execution'
        }
        & $binary -u 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Official Sysmon uninstall failed' }
    }
    if ((Get-SysmonServiceCount) -ne 0) {
        throw 'Sysmon service/driver persists after uninstall'
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $root) { throw 'Owned Sysmon diagnostic files remain' }
    Write-Output 'JDC_SYSMON_DIAG_CLEANUP=PASS'
}

switch ($Mode) {
    'Start' {
        if ((Get-SysmonServiceCount) -ne 0 -or (Test-Path -LiteralPath $root)) {
            throw 'Pre-existing Sysmon service or state: refuse to override'
        }
        $isAdmin = ([Security.Principal.WindowsPrincipal] (
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (!$isAdmin) { throw 'Privileged disposable runner required for Sysmon installation' }
        New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
        $state = [pscustomobject]@{
            Owned = $true
            InstallAttempted = $false
            CalibrationName = 'JDC-Sysmon-Calibration-' + [guid]::NewGuid().ToString('N')
            StartedUtc = $null
        }
        Write-SourceState $state
        $probe = Join-Path 'HKCU:\Software' $state.CalibrationName
        $unwatched = Join-Path 'HKCU:\Software' ('JDC-Sysmon-Unwatched-' +
            [guid]::NewGuid().ToString('N'))
        try {
            $zip = Join-Path $root 'Microsoft-Sysmon.zip'
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -TimeoutSec 70
            if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -cne $expectedZip) {
                throw 'Microsoft Sysmon archive SHA256 mismatch'
            }
            $binFolder = Join-Path $root 'bin'
            Expand-Archive -LiteralPath $zip -DestinationPath $binFolder
            if (!(Test-Path -LiteralPath $binary -PathType Leaf) -or
                (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne $expectedBinary) {
                throw 'Microsoft Sysmon binary digest mismatch'
            }
            $signature = Get-AuthenticodeSignature -FilePath $binary
            if ($signature.Status -ne 'Valid' -or
                $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                throw 'Microsoft Sysmon signature did not validate'
            }
            if ((Get-Item -LiteralPath $binary).VersionInfo.FileVersion -cne '15.22') {
                throw 'Microsoft Sysmon binary version mismatch'
            }
            $xml = Get-JdcSysmonDiagnosticConfig -CalibrationName $state.CalibrationName
            $configPath = Join-Path $root 'config.xml'
            $xml | Set-Content -LiteralPath $configPath -Encoding UTF8
            $state.InstallAttempted = $true
            Write-SourceState $state
            & $binary -accepteula -i $configPath 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0 -or (Get-SysmonServiceCount) -lt 1) {
                throw 'Official Sysmon installation or service health failed'
            }
            $since = (Get-Date).ToUniversalTime()
            Start-Sleep -Milliseconds 500
            New-Item -Path $probe -ErrorAction Stop | Out-Null
            New-Item -Path $unwatched -ErrorAction Stop | Out-Null
            Start-Sleep -Milliseconds 850
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $paths = @{
                ('HKU\' + $sid + '\Software\' + $state.CalibrationName) = 'CALIBRATION'
                ('HKU\' + $sid + '\Software\' + (Split-Path -Leaf $unwatched)) = 'UNWATCHED'
            }
            $events = @(Get-Event12Since $since)
            $evidence = @(Select-ExactRegistryEvidence -events $events -paths $paths)
            $calibration = @($evidence | Where-Object {
                $_.KeyLabel -ceq 'CALIBRATION' -and $_.Operation -ceq 'CreateKey' -and
                $_.ProcessId -eq $PID -and
                $_.ImageName -ceq [IO.Path]::GetFileName((Get-Process -Id $PID).Path)
            })
            if ($calibration.Count -lt 1) {
                throw 'Exact-path Sysmon CreateKey PID/image calibration failed'
            }
            if (@($evidence | Where-Object { $_.KeyLabel -ceq 'UNWATCHED' }).Count -ne 0) {
                throw 'Sysmon include filter captured unrelated registry key'
            }
            $state.StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Write-SourceState $state
            Write-Output 'JDC_SYSMON_DIAG_EXACT_PATH_POSITIVE_NEGATIVE=PASS'
        } finally {
            if (Test-Path -LiteralPath $probe) {
                Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $unwatched) {
                Remove-Item -LiteralPath $unwatched -Force -ErrorAction Stop
            }
        }
    }
    'Report' {
        if (!(Test-Path -LiteralPath $stateFile)) {
            Write-Output 'JDC_SYSMON_DIAG_EVIDENCE=NOT_STARTED'
            break
        }
        $state = Get-SourceState
        if (!$state.StartedUtc) {
            Write-Output 'JDC_SYSMON_DIAG_EVIDENCE=CALIBRATION_NOT_COMPLETE'
            break
        }
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $pathPrefix = 'HKU\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\'
        $paths = @{
            ($pathPrefix + 'Run') = 'HKCU_RUN'
            ($pathPrefix + 'RunOnce') = 'HKCU_RUNONCE'
            'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = 'HKLM_RUN'
            'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' = 'HKLM_RUNONCE'
        }
        $events = @(Get-Event12Since ([datetime]::Parse($state.StartedUtc)))
        $evidence = @(Select-ExactRegistryEvidence -events $events -paths $paths)
        $installerPid = 0
        $pidFile = Join-Path $root 'installer-pid.txt'
        if (Test-Path -LiteralPath $pidFile) {
            $raw = (Get-Content -LiteralPath $pidFile -Raw).Trim()
            if (![int]::TryParse($raw, [ref]$installerPid) -or $installerPid -le 0) {
                throw 'Invalid installed candidate process ID evidence'
            }
        }
        if ($evidence.Count -eq 0) {
            Write-Output 'JDC_SYSMON_DIAG_RUNKEY_EVIDENCE=NO_EXACT_KEY_EVENTS'
        }
        foreach ($e in $evidence) {
            # Sanitized process basename only; no registry data, users or command lines.
            Write-Output ('JDC_SYSMON_DIAG_KEY_EVENT=key=' + $e.KeyLabel +
                ';operation=' + $e.Operation + ';image=' + $e.ImageName +
                ';pid=' + $e.ProcessId +
                ';pidEqualsRecordedInstaller=' + [bool]($installerPid -gt 0 -and
                    $e.ProcessId -eq $installerPid))
        }
        Write-Output ('JDC_SYSMON_DIAG_EXACT_EVENT_COUNT=' + $evidence.Count)
    }
    'Stop' { Uninstall-OwnedSysmon }
}
