# Staged, reboot-safe provisioning entry point (run at first logon, then by the LabResume startup task).
. C:\lab\common.ps1
Register-ResumeTask
$c = Get-LabConfig
Write-LabLog "boot.ps1 role=$($c.role) stage=$(Get-Stage)"
# Static address on the lab network; DNS points at dc1 (the DC points at itself)
$nic = Get-NetAdapter | ? Status -eq Up | Select-Object -First 1
if (-not (Get-NetIPAddress -IPAddress $c.ip -ErrorAction SilentlyContinue)) {
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $c.ip -PrefixLength 24 -DefaultGateway ($c.ip -replace '\.\d+$', '.1') | Out-Null
}
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $c.dcIp
# lab is isolated test infrastructure: no telemetry nags, but Defender and firewall stay ON
if ($c.role -eq 'dc') { & C:\lab\dc.ps1 } else { & C:\lab\member.ps1 }
