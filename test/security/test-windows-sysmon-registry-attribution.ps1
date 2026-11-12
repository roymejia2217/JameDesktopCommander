# Executable unit contract. Synthetic Sysmon Event 12 XML, no service/registry writes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../scripts/windows-sysmon-registry-attribution.ps1')

$sid = 'S-1-5-21-111-222-333-1001'
$run = 'HKU\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\Run'
$runOnce = 'HKU\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$calibration = 'HKU\' + $sid + '\Software\JDC-Sysmon-Calibration-aadeef'

function EventXml(
    [string]$target,
    [string]$kind = 'CreateKey',
    [string]$id = '12',
    [string]$provider = 'Microsoft-Windows-Sysmon',
    [string]$pidValue = '4242'
) {
    return @"
<Event>
<System>
<Provider Name="$provider"/>
<EventID>$id</EventID>
</System>
<EventData>
<Data Name="RuleName">JDC</Data>
<Data Name="EventType">$kind</Data>
<Data Name="UtcTime">2026-11-11 01:02:03.000</Data>
<Data Name="ProcessGuid">{865A03B7-A001-4000-8000-008000000111}</Data>
<Data Name="ProcessId">$pidValue</Data>
<Data Name="Image">C:\Users\Private\UserFolder\Installer.exe</Data>
<Data Name="TargetObject">$target</Data>
<Data Name="User">SENSITIVE_USER</Data>
</EventData>
</Event>
"@
}
function Assert-True($predicate, [string]$message) {
    if (!$predicate) { throw $message }
}
$watch = @{
    $run = 'HKCU_RUN'
    $runOnce = 'HKCU_RUNONCE'
    $calibration = 'CALIBRATION'
}
$record = ConvertTo-JdcSysmonRegistryEvidence -XmlText (EventXml $run) -ExactPaths $watch
Assert-True ($null -ne $record) 'Expected exact HKCU Run event'
Assert-True ($record.KeyLabel -ceq 'HKCU_RUN') 'Incorrect target label'
Assert-True ($record.Operation -ceq 'CreateKey') 'Incorrect event operation'
Assert-True ($record.ProcessId -eq 4242) 'Incorrect process id'
Assert-True ($record.ImageName -ceq 'Installer.exe') 'Incorrect sanitized image basename'
Assert-True ($record.ProcessGuid -ceq '{865a03b7-a001-4000-8000-008000000111}') 'Incorrect ProcessGuid'
Assert-True ($record.PSObject.Properties.Name -notcontains 'TargetObject') 'Private registry path exported'
Assert-True ($record.PSObject.Properties.Name -notcontains 'User') 'Private username exported'
Assert-True ($record.PSObject.Properties.Name -notcontains 'CommandLine') 'Process command line exported'
Assert-True (!(($record | ConvertTo-Json -Compress).Contains('UserFolder'))) 'Sensitive image path exposed'
$once = ConvertTo-JdcSysmonRegistryEvidence -XmlText (EventXml $runOnce 'DeleteKey') -ExactPaths $watch
Assert-True ($once.KeyLabel -ceq 'HKCU_RUNONCE') 'RunOnce label mismatch'
Assert-True ($once.Operation -ceq 'DeleteKey') 'RunOnce operation mismatch'
$cal = ConvertTo-JdcSysmonRegistryEvidence -XmlText (EventXml $calibration) -ExactPaths $watch
Assert-True ($cal.KeyLabel -ceq 'CALIBRATION') 'Calibration label mismatch'
$excluded = @(
    (EventXml ($run+'\Other')),
    (EventXml ($run+'OnceExtra')),
    (EventXml ('HKU\S-1-5-21-999-222-333-1001\Software\Microsoft\Windows\CurrentVersion\Run')),
    (EventXml ('HKLM\Software\Microsoft\Windows\CurrentVersion\Run')),
    (EventXml $run 'SetValue'),
    (EventXml $run 'CreateKey' '13'),
    (EventXml $run 'CreateKey' '12' 'Unexpected-Provider')
)
foreach ($xml in $excluded) {
    $found = ConvertTo-JdcSysmonRegistryEvidence -XmlText $xml -ExactPaths $watch
    Assert-True ($null -eq $found) 'Non-exact or wrong event was attributed'
}
$badPid = $false
try {
    $null = ConvertTo-JdcSysmonRegistryEvidence -XmlText (EventXml $run 'CreateKey' '12' 'Microsoft-Windows-Sysmon' '-1') -ExactPaths $watch
} catch { $badPid = $true }
Assert-True $badPid 'Invalid event PID did not fail closed'
Write-Output 'WINDOWS_SYSMON_EXACT_REGISTRY_ATTRIBUTION_TEST=PASS'

$config = Get-JdcSysmonDiagnosticConfig -CalibrationName 'JDC-Sysmon-Calibration-aadeef'
[xml]$configDoc = $config
$filter = $configDoc.Sysmon.EventFiltering.RegistryEvent
Assert-True ($filter.onmatch -ceq 'include') 'Sysmon registry filter not include-only'
$ruleTexts = @($filter.TargetObject | ForEach-Object { $_.InnerText })
$expectedRuleTexts = @(
    '\Software\Microsoft\Windows\CurrentVersion\Run',
    '\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'JDC-Sysmon-Calibration-aadeef'
)
Assert-True ($ruleTexts.Count -eq 3) 'Sysmon filter rule count mismatch'
foreach ($expected in $expectedRuleTexts) {
    Assert-True ($ruleTexts -ccontains $expected) 'Expected scoped diagnostic rule missing'
}
Assert-True ($config -notmatch '<ProcessCreate') 'Broad process tracking enabled'
Assert-True ($config -notmatch '<NetworkConnect') 'Broad network tracking enabled'
Write-Output 'WINDOWS_SYSMON_SCOPED_CONFIG_TEST=PASS'

$unsafeImageRejected = $false
try {
    $malicious = (EventXml $run).Replace('Installer.exe', 'Installer.exe&#10;::error::SPOOFED')
    $null = ConvertTo-JdcSysmonRegistryEvidence -XmlText $malicious -ExactPaths $watch
} catch { $unsafeImageRejected = $true }
Assert-True $unsafeImageRejected 'Untrusted image name could inject a workflow log command'
$invalidGuidRejected = $false
try {
    $invalid = (EventXml $run).Replace('{865A03B7-A001-4000-8000-008000000111}', 'INVALID_GUID')
    $null = ConvertTo-JdcSysmonRegistryEvidence -XmlText $invalid -ExactPaths $watch
} catch { $invalidGuidRejected = $true }
Assert-True $invalidGuidRejected 'Invalid Sysmon ProcessGuid did not fail closed'
Write-Output 'WINDOWS_SYSMON_MALFORMED_EVENT_FAIL_CLOSED_TEST=PASS'

$unsafeLogTokenRejected = $false
try {
    $logToken = (EventXml $run).Replace('Installer.exe', 'Installer.exe::error::FORGED_CI_STATUS')
    $null = ConvertTo-JdcSysmonRegistryEvidence -XmlText $logToken -ExactPaths $watch
} catch { $unsafeLogTokenRejected = $true }
Assert-True $unsafeLogTokenRejected 'Untrusted image basename contains a CI log control token'
Write-Output 'WINDOWS_SYSMON_LOG_TOKEN_REJECTION_TEST=PASS'

$workflow = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../.github/workflows/distribution-candidate.yml') -Raw
$guard = "github.head_ref == 'diagnostics/issue270-sysmon-runkey-attribution-20261111' && github.event.pull_request.head.repo.full_name == github.repository"
Assert-True (([regex]::Matches($workflow, [regex]::Escape($guard))).Count -eq 4) 'Diagnostic branch+owner guards missing'
Assert-True ($workflow.Contains('Verify Windows installer install and uninstall')) 'Original acceptance gate missing'
Assert-True ($workflow.Contains('Assert-HostPackageBoundary')) 'Original startup registry no-drift gate missing'
Assert-True ($workflow.Contains('always() && matrix.target')) 'Guaranteed Sysmon cleanup condition missing'
Assert-True ($workflow.Contains('-Mode Stop')) 'Owned Sysmon cleanup not invoked'
Write-Output 'WINDOWS_SYSMON_DIAGNOSTIC_NO_GATE_BYPASS_TEST=PASS'
