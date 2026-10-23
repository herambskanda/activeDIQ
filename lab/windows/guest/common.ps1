# Shared helpers for the lab guest scripts. Config: C:\lab\lab.json (copied from the CIDATA CD; holds
# generated per-run secrets). Never write a secret to the log.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LabDir = 'C:\lab'
function Get-LabConfig { Get-Content "$script:LabDir\lab.json" -Raw | ConvertFrom-Json }
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
