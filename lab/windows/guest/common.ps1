# Shared helpers for the lab guest scripts. Config: C:\lab\lab.json (copied from the CIDATA CD; holds
# generated per-run secrets). Never write a secret to the log.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LabDir = 'C:\lab'
function Get-LabConfig { Get-Content "$script:LabDir\lab.json" -Raw | ConvertFrom-Json }
# Re-runnable scripts (audit-gpo, entra-ready) must work after Remove-LabSecrets deleted lab.json: fall back to
# the directory itself. userPassword is $null then; only needed when a missing account has to be created.
function Get-LabContext {
  if (Test-Path "$script:LabDir\lab.json") { return Get-LabConfig }
  $d = Get-ADDomain
  [pscustomobject]@{ baseDn = $d.DistinguishedName; domain = $d.DNSRoot; userPassword = $null }
}
function Write-LabLog([string]$m) { "$(Get-Date -Format o) $m" | Add-Content "$script:LabDir\provision.log" }
function Get-Stage { if (Test-Path "$script:LabDir\stage") { (Get-Content "$script:LabDir\stage").Trim() } else { 'start' } }
function Set-Stage([string]$s) { Set-Content "$script:LabDir\stage" $s; Write-LabLog "stage -> $s" }
function Register-ResumeTask {
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\lab\boot.ps1'
  Register-ScheduledTask -TaskName LabResume -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Force | Out-Null
}
function Remove-LabSecrets {  # after the last stage the secrets file and answer file are deleted from the guest
  Remove-Item "$script:LabDir\lab.json", "$script:LabDir\autounattend.xml" -Force -ErrorAction SilentlyContinue
}
function ConvertTo-Secure([string]$p) { ConvertTo-SecureString $p -AsPlainText -Force }
# Random per-run lab password (Wl-<28 hex>-aA1!). Shared by external-init.ps1 and child-dc.ps1 (T-1233).
function New-LabPassword { $b = New-Object byte[] 14; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'Wl-' + (($b | ForEach-Object { $_.ToString('x2') }) -join '') + '-aA1!' }
# Restrict a file to SYSTEM + Administrators (no inherited ACEs). Call it BEFORE a secret is written to the file.
function Protect-LabFile([string]$path) { icacls $path /inheritance:r /grant:r 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null }
