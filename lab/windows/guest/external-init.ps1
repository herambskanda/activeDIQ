# Human-run, inside an existing Windows Server VM (Proxmox VM 112) that becomes dc1 (T-0428).
# Run once as Administrator from the repo's lab\windows\guest folder copied to the VM:
#   powershell -ExecutionPolicy Bypass -File .\external-init.ps1 -DcIp <static ip of this VM>
# It creates C:\lab with the guest scripts and a lab.json holding RANDOM per-run passwords (never in git),
# then writes C:\lab\win-lab.env (same passwords, host-side format) for you to copy to the lab host with scp.
# Afterwards start the staged, reboot-safe provisioning:  powershell -ExecutionPolicy Bypass -File C:\lab\boot.ps1
# The VM must already be named DC1 with the static IP set (runbook: "Prepare VM 112"). Passwords are never printed.
param([Parameter(Mandatory)][string]$DcIp)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'DC1') { throw "computer name is '$env:COMPUTERNAME', must be DC1 (Rename-Computer -NewName DC1 -Restart)" }
if (-not (Get-NetIPAddress -IPAddress $DcIp -ErrorAction SilentlyContinue)) { throw "$DcIp is not configured on this VM; set the static IP first" }
if (Test-Path C:\lab\lab.json) { throw 'C:\lab\lab.json exists: provisioning already started; delete C:\lab to start over' }
New-Item -ItemType Directory -Force C:\lab | Out-Null
Copy-Item "$PSScriptRoot\*.ps1" C:\lab\ -Exclude external-init.ps1, child-dc-init.ps1 -Force
. "$PSScriptRoot\common.ps1"   # New-LabPassword, Protect-LabFile (shared helpers; not forked here)
$p = [ordered]@{ admin = New-LabPassword; dsrm = New-LabPassword; svc = New-LabPassword; user = New-LabPassword }
$id = (New-LabPassword).Substring(3, 12)
# The local Administrator password becomes the first domain Administrator password on promotion.
Set-LocalUser -Name Administrator -Password (ConvertTo-SecureString $p.admin -AsPlainText -Force)
@{ role = 'dc'; external = $true; ip = $DcIp; domain = 'win.activediq.test'; netbios = 'WINLAB'; dcIp = $DcIp
   baseDn = 'DC=win,DC=activediq,DC=test'; adminPassword = $p.admin; dsrmPassword = $p.dsrm; svcPassword = $p.svc
   userPassword = $p.user } | ConvertTo-Json | Set-Content C:\lab\lab.json -Encoding ascii
@("WIN_LAB_ID=$id", "WIN_LAB_ADMIN_PASSWORD=$($p.admin)", "WIN_LAB_DSRM_PASSWORD=$($p.dsrm)",
  "WIN_LAB_SVC_PASSWORD=$($p.svc)", "WIN_LAB_USER_PASSWORD=$($p.user)") | Set-Content C:\lab\win-lab.env -Encoding ascii
foreach ($f in 'C:\lab\lab.json', 'C:\lab\win-lab.env') {   # SYSTEM + Administrators only
  Protect-LabFile $f
}
Write-Host 'C:\lab ready. Copy C:\lab\win-lab.env to the lab host (mode 0600), then delete it from the VM. Next: C:\lab\boot.ps1'
