<#
 T-0635 lab driver (TM-TB16-T1, HOST-DC-REFUSED). Run elevated on dc1 (and on fs1 as the control, where the
 install must succeed). It runs the MSI silently, then observes what happened and prints the Observation JSON
 that `go run ./tools/fitness/host evaluate` judges:

   .\Test-MsiRefusesDc.ps1 -MsiPath C:\lab\ActiveDIQ-Server.msi -LogPath C:\lab\msi.log > obs.json
   go run ./tools/fitness/host evaluate obs.json

 Expected on a DC: msiexec exits 1603 (a launch condition failed), the log holds the DC message, and no
 install directory, service or Uninstall entry exists. Start-Process -ArgumentList joins its array
 with single spaces and does no quoting (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process),
 so an array is not a safe primitive by itself. Both paths are therefore resolved to full paths, refused if
 they contain a double quote or begin with '/' or '-' (a path such as 'x.msi /a' must not become an msiexec
 switch; /a skips LaunchConditions), and each is wrapped in explicit double quotes.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$MsiPath,
  [Parameter(Mandatory)][string]$LogPath,
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'activeDIQ'),
  [string]$ServiceName = 'activeDIQServer'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) { throw "MSI not found: $MsiPath" }
function Assert-SafeMsiexecPath([string]$Name, [string]$Value) {
  if ($Value.Contains('"') -or $Value.StartsWith('/') -or $Value.StartsWith('-')) { throw "$Name is not a safe msiexec argument: $Value" }
}
$MsiPath = [IO.Path]::GetFullPath($MsiPath)
$LogPath = [IO.Path]::GetFullPath($LogPath)
Assert-SafeMsiexecPath 'MsiPath' $MsiPath
Assert-SafeMsiexecPath 'LogPath' $LogPath
if (Test-Path -LiteralPath $LogPath) { Remove-Item -LiteralPath $LogPath -Force }

$productType = (Get-CimInstance Win32_OperatingSystem).ProductType   # 1 workstation, 2 DC, 3 server
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole           # 4/5 = DC
if (($productType -eq 2) -ne ($role -ge 4)) { throw "ProductType $productType and DomainRole $role disagree about domain controller" }

$msiArgs = @('/i', ('"{0}"' -f $MsiPath), '/qn', '/norestart', '/l*v', ('"{0}"' -f $LogPath))
$p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
$log = if (Test-Path -LiteralPath $LogPath) { Get-Content -LiteralPath $LogPath -Raw } else { '' }
$msg = 'cannot be installed on a domain controller'

$leftovers = @()
if (Test-Path -LiteralPath $InstallDir) { $leftovers += "directory $InstallDir" }
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { $leftovers += "service $ServiceName" }
$uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
# Uninstall subkeys without a DisplayName are normal; read the value through the key, not as a strict-mode property.
$hasEntry = $false
foreach ($k in Get-ChildItem -LiteralPath $uninst -ErrorAction SilentlyContinue) {
  if ($k.GetValue('DisplayName') -eq 'activeDIQ Server') { $hasEntry = $true }
}
if ($hasEntry) { $leftovers += 'Uninstall entry' }
foreach ($l in $leftovers) { [Console]::Error.WriteLine("leftover after msiexec: $l") }

$refused = ($p.ExitCode -ne 0) -and $log.Contains($msg)
if ($role -ge 4) {
  # What the lab must see on a DC. Fail loudly here so a mis-run is not mistaken for a pass.
  if ($p.ExitCode -ne 1603) { [Console]::Error.WriteLine("expected exit 1603 on a DC, got $($p.ExitCode)") }
  $result = if ($refused -and $leftovers.Count -eq 0) { 'refused' } else { 'installed' }
} else {
  $result = if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { 'installed' } else { 'refused' }
}
# Get-HostObservation re-reads the host itself and also marks 'installed' when it finds leftovers.
& (Join-Path $PSScriptRoot 'Get-HostObservation.ps1') -InstallDir $InstallDir -ServiceName '' -InstallerResult $result -ProbeInstallDir $InstallDir -ProbeServiceName $ServiceName
