<#
 TM-F-HOST Windows collector (T-0136). Run on a Windows lab host (dc1 for -DomainController, fs1 for the install)
 from an elevated prompt; it prints one Observation JSON document (the contract in
 tools/fitness/host/hostcheck/obs.go) which `go run ./tools/fitness/host evaluate` judges. It observes; it
 never changes the host. A section it cannot observe is omitted and the case is reported INACTIVE.

 -ServiceName     the installed activeDIQ service (omit before the MSI exists: service/files/dumps stay unobserved)
 -InstallDir      the install directory, whose ACL is read
 -ConfigPaths     config, keystore and TLS-directory paths to ACL-check
 -InstallerResult 'refused' | 'installed': what the installer did on this host (the lab run supplies it)
#>
[CmdletBinding()]
param(
  [string]$ServiceName,
  [string]$InstallDir,
  [string[]]$ConfigPaths = @(),
  [ValidateSet('', 'refused', 'installed')][string]$InstallerResult = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$obs = [ordered]@{ profile = 'windows' }

# DomainRole: 4 = backup DC, 5 = primary DC (Win32_ComputerSystem).
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
if ($InstallerResult -ne '') {
  $obs.installer = [ordered]@{
    on_domain_controller = ($role -ge 4)
    refused              = ($InstallerResult -eq 'refused')
    installed            = ($InstallerResult -eq 'installed')
  }
}

# Principals that may read: the service identity, SYSTEM, Administrators, TrustedInstaller, CREATOR OWNER.
$allowedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Get-FileObs([string]$Path, [string]$Kind, [string[]]$AlsoAllowed) {
  $acl = Get-Acl -LiteralPath $Path
  $others = @(); $writers = @()
  foreach ($r in $acl.Access) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if (($allowedSids + $AlsoAllowed) -contains $sid) { continue }
    $fsr = [int]$r.FileSystemRights
    if ($fsr -band (0x1 -bor 0x20 -bor 0x80000000 -bor 0x10000000 -bor 0x1F01FF)) { $others += $sid } # ReadData/Execute/GenericRead/GenericAll/FullControl
    if ($fsr -band (0x2 -bor 0x4 -bor 0x40000000 -bor 0x10000000 -bor 0x40 -bor 0x100)) { $writers += $sid }
  }
  [ordered]@{ path = $Path; kind = $Kind; readable_by_others = ($others.Count -gt 0); writable_by_others = ($writers.Count -gt 0); owner = [string]$acl.Owner }
}

$svcSid = $null
if ($ServiceName) {
  $svc = Get-CimInstance Win32_Service -Filter "Name='$($ServiceName -replace "'", "''")'"
  if (-not $svc) { throw "service $ServiceName not found" }
  $acct = [string]$svc.StartName
  $obs.service = [ordered]@{ account = $acct }
  try { $svcSid = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
}
$files = @()
if ($InstallDir) { $files += Get-FileObs $InstallDir 'binary' @($svcSid) }
foreach ($p in $ConfigPaths) {
  $kind = if ((Get-Item -LiteralPath $p).PSIsContainer) { 'tls-dir' } else { 'config' }
  $files += Get-FileObs $p $kind @($svcSid)
}
if ($files.Count -gt 0) { $obs.files = $files }

if ($ServiceName) {
  # WER LocalDumps: the key exists globally or per image name.
  $img = Split-Path -Leaf (($svc.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1')
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
  $wer = (Test-Path -LiteralPath $base) -and ((Get-ItemProperty -LiteralPath $base -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains 'DumpFolder' -or (Test-Path -LiteralPath (Join-Path $base $img)))
  $envBlock = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction SilentlyContinue).Environment
  $obs.dumps = [ordered]@{ wer_local_dumps = [bool]$wer; traceback_crash = [bool]($envBlock -match '^GOTRACEBACK=crash$'); pprof_listens = $false; core_limit_zero = $false; not_dumpable = $false }
}
$obs | ConvertTo-Json -Depth 6
