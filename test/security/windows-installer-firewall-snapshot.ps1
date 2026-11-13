# Full machine-persistent firewall inventory; called only by the hosted runner's
# privileged observer, never by the unprivileged installer child.
function Get-FirewallSnapshot {
  $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object Name | ForEach-Object {
      $_.Name + '|' + $_.DisplayName + '|' + $_.Enabled + '|' + $_.Direction + '|' + $_.Action
    })
  $ports = @(Get-NetFirewallPortFilter -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object InstanceID | ForEach-Object {
      $_.InstanceID + '|' + $_.Protocol + '|' + ($_.LocalPort -join ',') + '|' + ($_.RemotePort -join ',')
    })
  $applications = @(Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -ErrorAction Stop |
    Sort-Object InstanceID | ForEach-Object { $_.InstanceID + '|' + $_.Program })
  return ((@($rules) + @($ports) + @($applications)) -join [char]10)
}

# Called with OS-read snapshots from the privileged host observer at each
# bounded checkpoint; never substitutes the unprivileged installer identity.
function Assert-HostFirewallSnapshotUnchanged {
  param(
    [Parameter(Mandatory)][string]$Before,
    [Parameter(Mandatory)][string]$Current,
    [Parameter(Mandatory)][ValidateSet('INSTALLED','UNINSTALLED')][string]$Phase
  )
  if ($Current -cne $Before) {
    throw ("E_INSTALLER_FIREWALL_DRIFT_" + $Phase)
  }
}
