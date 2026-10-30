<#
 T-0613 lab harness (for T-0557): create the DC agent's service identity exactly as ADR-0006 pins it, on a
 Windows host, and capture the evidence.
   - service runs as the virtual account  NT SERVICE\activeDIQAgent  (never LocalSystem)
   - service SID type RESTRICTED
   - RequiredPrivileges = SeChangeNotifyPrivilege only
   - data dir %ProgramData%\skenzeriq\agent: DACL = service SID + SYSTEM + Administrators, protected
 The service binary is the lab stub (svcstub.exe, built by `make windows-agent-harness-build`); the real agent
 has no service host or MSI yet. LAB USE ONLY: this is not the installer. Idempotent; -Uninstall removes it all.
 Run elevated:  powershell -ExecutionPolicy Bypass -File Install-AgentLabHarness.ps1 -BinaryPath C:\lab\agent-harness\svcstub.exe
 Evidence lands in -EvidenceDir (default C:\lab\agent-harness-evidence). Exit non-zero on any failed check.
 All native commands take structured argv (no string-built command lines); ACLs use typed .NET APIs.
 Refs: sc.exe sidtype / privs / qprivs https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config
       virtual accounts https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts
#>
[CmdletBinding()]
param(
  [string]$BinaryPath = 'C:\lab\agent-harness\svcstub.exe',
  [string]$EvidenceDir = 'C:\lab\agent-harness-evidence',
  [switch]$Uninstall
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Name    = 'activeDIQAgent'
$Account = "NT SERVICE\$Name"
$DataDir = Join-Path $env:ProgramData 'skenzeriq\agent'
$Pinned  = @('SeChangeNotifyPrivilege')   # ADR-0006 decision 3
$fail = 0
function Check([bool]$ok, [string]$what) { if ($ok) { "ok: $what" } else { "FAIL: $what"; $script:fail++ } }
function Sc([string[]]$a) {                # fixed argv to sc.exe; throws on non-zero exit
  $o = & "$env:SystemRoot\System32\sc.exe" @a 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe $($a -join ' ') failed ($LASTEXITCODE): $o" }
  $o
}
function Exists { $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue) }
function Stop-AndDelete {
  if (Exists) {
    & "$env:SystemRoot\System32\sc.exe" stop $Name 2>&1 | Out-Null
    for ($i = 0; $i -lt 20 -and (Get-Service $Name).Status -ne 'Stopped'; $i++) { Start-Sleep -Milliseconds 500 }
    Sc @('delete', $Name) | Out-Null
    for ($i = 0; $i -lt 20 -and (Exists); $i++) { Start-Sleep -Milliseconds 500 }
  }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) {
  throw 'run elevated (Administrators)'
}

if ($Uninstall) {
  Stop-AndDelete
  if (Test-Path -LiteralPath $DataDir) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
  Check (-not (Exists)) 'service removed'
  Check (-not (Test-Path -LiteralPath $DataDir)) 'data dir removed'
  Check (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name")) 'no service registry key left'
  if ($fail) { exit 1 }; exit 0
}

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) { throw "service binary not found: $BinaryPath" }
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

# 1. service: recreate for idempotence. obj= NT SERVICE\<name> selects the virtual account (no password).
Stop-AndDelete
Sc @('create', $Name, 'binPath=', "`"$BinaryPath`"", 'obj=', $Account, 'start=', 'demand', 'DisplayName=', 'activeDIQ Agent (lab harness)') | Out-Null
Sc @('sidtype', $Name, 'restricted') | Out-Null
Sc @('privs', $Name, ($Pinned -join '/')) | Out-Null
Sc @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000//') | Out-Null

# 2. data dir with a typed, protected DACL: service SID + SYSTEM + Administrators only.
$svcSid = (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier])
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$sd = New-Object Security.AccessControl.DirectorySecurity
$sd.SetAccessRuleProtection($true, $false)
$inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @($svcSid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
  $sd.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inh, 'None', 'Allow')))
}
Set-Acl -LiteralPath $DataDir -AclObject $sd
Get-ChildItem -LiteralPath $DataDir -Force | Remove-Item -Force -Recurse   # stale evidence from earlier runs

# 3. start and wait for the stub's capture ("done" marker).
Sc @('start', $Name) | Out-Null
for ($i = 0; $i -lt 40 -and -not (Test-Path (Join-Path $DataDir 'done')); $i++) { Start-Sleep -Milliseconds 500 }
Check (Test-Path (Join-Path $DataDir 'done')) 'service started and wrote its token capture'

# 4. evidence + checks
$sc = "$env:SystemRoot\System32\sc.exe"
& $sc qc $Name       | Set-Content (Join-Path $EvidenceDir 'sc-qc.txt')
& $sc qprivs $Name   | Set-Content (Join-Path $EvidenceDir 'sc-qprivs.txt')
& $sc qsidtype $Name | Set-Content (Join-Path $EvidenceDir 'sc-qsidtype.txt')
& $sc query $Name    | Set-Content (Join-Path $EvidenceDir 'sc-query.txt')
(Get-Acl -LiteralPath $DataDir).Sddl | Set-Content (Join-Path $EvidenceDir 'datadir-sddl.txt')
Get-ComputerInfo -Property WindowsProductName, OsVersion, OsBuildNumber, WindowsVersion | Format-List | Out-File (Join-Path $EvidenceDir 'os.txt')
foreach ($f in 'whoami-priv.txt', 'whoami-user.txt', 'whoami-groups.txt') {
  if (Test-Path (Join-Path $DataDir $f)) { Copy-Item (Join-Path $DataDir $f) (Join-Path $EvidenceDir $f) -Force }
}

Check ((& $sc qc $Name | Out-String) -match [regex]::Escape("SERVICE_START_NAME : $Account")) "service account is $Account"
Check (-not ((& $sc qc $Name | Out-String) -match 'LocalSystem')) 'not LocalSystem'
Check ((& $sc qsidtype $Name | Out-String) -match 'RESTRICTED') 'service SID type is RESTRICTED'
$req = @(Select-String -InputObject ((& $sc qprivs $Name) | Out-String) -Pattern 'Se\w+Privilege' -AllMatches | ForEach-Object { $_.Matches.Value } | Sort-Object -Unique)
Check (($req -join ',') -eq ($Pinned -join ',')) "RequiredPrivileges == $($Pinned -join ',') (got: $($req -join ','))"

$privFile = Join-Path $EvidenceDir 'whoami-priv.txt'
if (Test-Path $privFile) {
  $held = @(Select-String -Path $privFile -Pattern '\b(Se\w+Privilege)\b' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique)
  Check (($held -join ',') -eq ($Pinned -join ',')) "whoami /priv inside the service lists only $($Pinned -join ',') (got: $($held -join ','))"
  $acc = Select-String -Path (Join-Path $EvidenceDir 'whoami-user.txt') -Pattern 'nt service\\activediqagent' -Quiet
  Check $acc 'whoami /user inside the service reports nt service\activediqagent'
} else { Check $false 'whoami /priv capture present' }

$dacl = Get-Acl -LiteralPath $DataDir
$sids = @($dacl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
Check ((($sids) -join ',') -eq ((@($svcSid.Value, 'S-1-5-18', 'S-1-5-32-544') | Sort-Object) -join ',')) 'data dir DACL = service SID + SYSTEM + Administrators'
Check $dacl.AreAccessRulesProtected 'data dir inheritance disabled'

# binary directory must not be writable by the service SID (ADR-0006 decision 5). Informational ACL dump + check.
$binDir = Split-Path -Parent $BinaryPath
$bad = @((Get-Acl -LiteralPath $binDir).Access | Where-Object {
  $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]'WriteData,AppendData,Delete,ChangePermissions') -and
  $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $svcSid.Value })
Check ($bad.Count -eq 0) 'binary directory grants the service SID no write access'

"result: $(if ($fail) { "FAILED ($fail)" } else { 'PASS' }) evidence in $EvidenceDir"
if ($fail) { exit 1 }
