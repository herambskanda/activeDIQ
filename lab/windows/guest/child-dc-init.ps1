# Human-run, inside a fresh Windows Server VM (Proxmox) that becomes dc2, the child-domain DC (T-1233).
# Run once as Administrator from the repo's lab\windows\guest folder copied to the VM:
#   powershell -ExecutionPolicy Bypass -File .\child-dc-init.ps1 -ParentDcIp <static ip of dc1> -Dc2Ip <static ip of this VM>
# It checks the VM is ready (name DC2, static IP, DNS = dc1, parent domain resolvable), creates C:\lab with the guest
# scripts and a lab.json that holds NO secret (no password is generated or needed here), and registers nothing else.
# Next: powershell -ExecutionPolicy Bypass -File C:\lab\boot.ps1   (interactive console: it prompts for the parent
# Administrator password as a SecureString, once; the DSRM password is generated at promotion, see child-dc.ps1).
param([Parameter(Mandatory)][string]$ParentDcIp, [Parameter(Mandatory)][string]$Dc2Ip)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$parent = 'win.activediq.test'
if ($env:COMPUTERNAME -ne 'DC2') { throw "computer name is '$env:COMPUTERNAME', must be DC2 (Rename-Computer -NewName DC2 -Restart)" }
if (-not (Get-NetIPAddress -IPAddress $Dc2Ip -ErrorAction SilentlyContinue)) { throw "$Dc2Ip is not configured on this VM; set the static IP first" }
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses })
if ($dns -notcontains $ParentDcIp) { throw "DNS client is [$($dns -join ',')]; it must include dc1 ($ParentDcIp): Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $ParentDcIp" }
if (-not (Resolve-DnsName "_ldap._tcp.dc._msdcs.$parent" -Type SRV -Server $ParentDcIp -ErrorAction SilentlyContinue)) { throw "dc1 ($ParentDcIp) does not resolve the $parent DC locator records" }
if (Test-Path C:\lab\lab.json) { throw 'C:\lab\lab.json exists: provisioning already started; delete C:\lab to start over' }
New-Item -ItemType Directory -Force C:\lab | Out-Null
Copy-Item "$PSScriptRoot\*.ps1" C:\lab\ -Exclude external-init.ps1, child-dc-init.ps1 -Force
. "$PSScriptRoot\common.ps1"   # Protect-LabFile (shared helper; not forked here)
# external = $true: boot.ps1 leaves the NIC alone (the human set IP and DNS). domain/netbios/dcIp are the PARENT's.
@{ role = 'child-dc'; external = $true; ip = $Dc2Ip; dcIp = $ParentDcIp; domain = $parent; netbios = 'WINLAB'
   childName = 'child'; childNetbios = 'WINCHILD' } | ConvertTo-Json | Set-Content C:\lab\lab.json -Encoding ascii
Protect-LabFile C:\lab\lab.json
Write-Host 'C:\lab ready (no secrets in it). Next, in an elevated console on this VM: powershell -ExecutionPolicy Bypass -File C:\lab\boot.ps1'
