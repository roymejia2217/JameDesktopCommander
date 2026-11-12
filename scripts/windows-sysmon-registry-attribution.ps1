# Pure, privacy-preserving Sysmon Event ID 12 parser. No service changes.
# Only exact, full HKU/HKLM targets supplied by the caller can be attributed.
function ConvertTo-JdcSysmonRegistryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$XmlText,
        [Parameter(Mandatory)][hashtable]$ExactPaths
    )
    [xml]$document = $XmlText
    $eventNode = $document.Event
    if ($null -eq $eventNode) { throw 'Missing Sysmon event root' }
    $providerNode = $eventNode.System.Provider
    if ($providerNode.GetAttribute('Name') -cne 'Microsoft-Windows-Sysmon' -or
        [string]$eventNode.System.EventID -cne '12') { return $null }
    $fields = @{}
    foreach ($item in @($eventNode.EventData.Data)) {
        if ($item -is [System.Xml.XmlElement]) {
            $fieldName = $item.GetAttribute('Name')
            if ($fieldName) { $fields[$fieldName] = $item.InnerText }
        }
    }
    if ($fields['EventType'] -cnotin @('CreateKey', 'DeleteKey')) {
        return $null
    }
    $targetObject = [string]$fields['TargetObject']
    $label = $null
    foreach ($candidate in $ExactPaths.Keys) {
        if ([string]::Equals($targetObject, [string]$candidate,
            [StringComparison]::OrdinalIgnoreCase)) {
            $label = [string]$ExactPaths[$candidate]
            break
        }
    }
    if (!$label) { return $null }
    $eventPid = 0
    if (![int]::TryParse([string]$fields['ProcessId'], [ref]$eventPid) -or
        $eventPid -le 0) { throw 'Invalid Sysmon registry process identifier' }
    $processGuid = [guid]::Empty
    if (![guid]::TryParse([string]$fields['ProcessGuid'], [ref]$processGuid) -or
        $processGuid -eq [guid]::Empty) { throw 'Invalid Sysmon process GUID' }
    $rawImage = [string]$fields['Image']
    if ($rawImage -cnotmatch '^[A-Za-z]:\\[^:\r\n]+$') {
        throw 'Invalid Sysmon source image path'
    }
    $image = [IO.Path]::GetFileName($rawImage)
    if (!$image -or $image -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ()._-]{0,127}$') {
        throw 'Invalid Sysmon image identity'
    }
    return [pscustomobject]@{
        KeyLabel = $label
        Operation = [string]$fields['EventType']
        ProcessId = $eventPid
        ProcessGuid = $processGuid.ToString('B')
        ImageName = $image
    }
}

# Scoped include-only filter; full-target identity is always checked again on read.
function Get-JdcSysmonDiagnosticConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CalibrationName)
    if ($CalibrationName -cnotmatch '^JDC-Sysmon-Calibration-[A-Za-z0-9]{6,40}$') {
        throw 'Invalid owned Sysmon calibration key name'
    }
    return @"
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RegistryEvent onmatch="include">
      <TargetObject condition="end with">\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
      <TargetObject condition="end with">\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">$CalibrationName</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
"@
}
