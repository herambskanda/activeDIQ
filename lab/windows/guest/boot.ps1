# Staged, reboot-safe provisioning entry point (run at first logon, then by the LabResume startup task).
. C:\lab\common.ps1
Register-ResumeTask
$c = Get-LabConfig
Write-LabLog "boot.ps1 role=$($c.role) stage=$(Get-Stage)"
try {
  # Static address on the lab network; DNS points at dc1 (the DC points at itself).
  # External host (lab.json "external": true, see external-init.ps1): the human already set the static IP; leave the NIC alone.
  $external = $c.PSObject.Properties.Name -contains 'external' -and $c.external
  if (-not $external) {
    $nic = Get-NetAdapter | ? Status -eq Up | Select-Object -First 1
    if (-not (Get-NetIPAddress -IPAddress $c.ip -ErrorAction SilentlyContinue)) {
      New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $c.ip -PrefixLength 24 -DefaultGateway ($c.ip -replace '\.\d+$', '.1') | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $c.dcIp
  }
  # lab is isolated test infrastructure: no telemetry nags, but Defender and firewall stay ON
  if ($c.role -eq 'dc') { & C:\lab\dc.ps1 } else { & C:\lab\member.ps1 }
} catch {
  # never die silently (T-0496): exception text only, no config values; the task re-runs at the next startup
  Write-LabLog "FAILED stage=$(Get-Stage): $($_.Exception.Message) at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
  exit 1
}
