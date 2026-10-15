#Requires -Version 5.1
<#
Native Task Scheduler S4U acceptance: isolated time-trigger repetition, clean
exit (0), intentional stop. No production task is touched, and all test objects
must be deleted in finally. A time trigger tests the repetition mechanism
without rebooting the machine; boot-trigger activation is a separate gate.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$fixture = Join-Path $repo 'test\fixtures\task-clean-exit.mjs'
if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) { throw 'Fixture missing' }
$node = (Get-Command node.exe -ErrorAction Stop).Source
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$folderName = 'JDC-Isolated-Test-' + [guid]::NewGuid().ToString('N')
$taskName = 'CleanExitRecurrence'
$tmp = Join-Path ([IO.Path]::GetTempPath()) $folderName
$receipt = Join-Path $tmp 'receipt.txt'
$service = New-Object -ComObject Schedule.Service
$service.Connect()
$root = $service.GetFolder('\')
$folder = $null
$registered = $false
New-Item -ItemType Directory -Path $tmp -ErrorAction Stop | Out-Null
try {
    $folder = $root.CreateFolder($folderName)
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description = 'Isolated JDC native task E2E'
    $definition.Settings.Enabled = $true
    $definition.Settings.Hidden = $true
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.StartWhenAvailable = $false
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT20S'
    $definition.Principal.UserId = $identity
    $definition.Principal.LogonType = 2
    $definition.Principal.RunLevel = 0
    $trigger = $definition.Triggers.Create(1)
    $trigger.StartBoundary = (Get-Date).AddSeconds(10).ToString('yyyy-MM-ddTHH:mm:ss')
    $trigger.Enabled = $true
    $trigger.Repetition.Interval = 'PT1M'
    $trigger.Repetition.StopAtDurationEnd = $false
    $action = $definition.Actions.Create(0)
    $action.Path = $node
    $action.Arguments = '"' + $fixture + '" "' + $receipt + '"'
    $action.WorkingDirectory = $repo
    $task = $folder.RegisterTaskDefinition($taskName,$definition,2,$identity,$null,2,$null)
    $registered = $true
    if ($task.Definition.Settings.MultipleInstances -ne 2) {
        throw 'IgnoreNew registration not preserved'
    }
    if ($task.Definition.Triggers.Item(1).Repetition.Interval -ne 'PT1M') {
        throw 'Repetition registration not preserved'
    }
    # Fixed bounded wait covers the scheduled first and second invocations.
    Start-Sleep -Seconds 85
    $lines = if (Test-Path -LiteralPath $receipt) {
        @(Get-Content -LiteralPath $receipt -ErrorAction Stop)
    } else { @() }
    if ($lines.Count -ne 2 -or
        @($lines | Where-Object { $_ -ne 'exit-zero' }).Count -ne 0) {
        throw ('Expected exactly two successful clean exits, got ' + $lines.Count)
    }
    $name = '\' + $folderName + '\' + $taskName
    $schtasks = (Get-Command schtasks.exe -ErrorAction Stop).Source
    & $schtasks /Change /TN $name /DISABLE *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Native DISABLE failed' }
    if ($folder.GetTask($taskName).Enabled) {
        throw 'Task remains enabled after intentional stop'
    }
    # Crossing the third scheduled firing is deliberate, not a polling loop.
    Start-Sleep -Seconds 70
    $after = @(Get-Content -LiteralPath $receipt -ErrorAction Stop)
    if ($after.Count -ne $lines.Count) {
        throw 'Task restarted after operator disabled it'
    }
    [pscustomobject]@{
        NativeTaskRegistered=$true
        LogonType='S4U'
        TestTrigger='TimeTrigger'
        Repetition='PT1M'
        IgnoreNew=$true
        CleanExitExecutions=$lines.Count
        ExecutionsAfterStop=$after.Count
        StopPreserved=$true
    } | ConvertTo-Json -Compress
}
finally {
    if ($folder) {
        if ($registered) {
            try {
                $existing = $folder.GetTask($taskName)
                if ($existing.State -eq 4) { $existing.Stop(0) }
                $folder.DeleteTask($taskName,0)
            } catch { Write-Warning 'Isolated task cleanup failed' }
        }
        try { $root.DeleteFolder($folderName,0) }
        catch { Write-Warning 'Isolated folder cleanup failed' }
    }
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop
    }
}
