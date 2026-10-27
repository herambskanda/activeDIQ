<#
 Lab test for T-0104 acceptance 1 (run on the Windows lab member, as Administrator):
   1. static: the directory ACL is protected and holds exactly Administrators + the service identity;
   2. behavioural (-ProbeCredential): a non-administrator local user cannot list or read the directory.
 Lab credentials are generated per run (knowledge/development/runbooks/windows-lab.md); never commit one.
 Exits non-zero on any failure.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Path,
  [Parameter(Mandatory)][string]$ServiceIdentity,
  [pscredential]$ProbeCredential
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fail = 0
function Check([bool]$ok, [string]$what) { if ($ok) { "ok: $what" } else { "FAIL: $what"; $script:fail++ } }

$svc = if ($ServiceIdentity -match '^S-1-') { $ServiceIdentity } else {
  (New-Object System.Security.Principal.NTAccount($ServiceIdentity)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
$want = @('S-1-5-32-544', $svc) | Sort-Object -Unique
$acl = Get-Acl -LiteralPath $Path
$sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
Check $acl.AreAccessRulesProtected 'inheritance is disabled'
Check ((@($acl.Access | Where-Object { $_.IsInherited })).Count -eq 0) 'no inherited entries'
Check (($sids -join ',') -eq ($want -join ',')) "ACL principals are exactly Administrators + service identity (got: $($sids -join ', '))"
Check (@($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }).Count -eq 0) 'no deny entries needed'

if ($ProbeCredential) {
  # The path is data, never script text: it travels in an environment variable read by a fixed script.
  $probe = @'
$p = $env:ADIQ_PROBE_PATH
try { Get-ChildItem -LiteralPath $p -ErrorAction Stop | Out-Null } catch [System.UnauthorizedAccessException] { exit 5 } catch { exit 9 }
exit 0
'@
  $probeFile = @'
$p = $env:ADIQ_PROBE_PATH
try { $f = Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop | Select-Object -First 1; if (-not $f) { exit 8 }; Get-Content -LiteralPath $f.FullName -TotalCount 1 -ErrorAction Stop | Out-Null } catch [System.UnauthorizedAccessException] { exit 5 } catch { exit 9 }
exit 0
'@
  $env:ADIQ_PROBE_PATH = $Path
  try {
    foreach ($case in @(@{n='list the directory'; s=$probe}, @{n='read a file inside'; s=$probeFile})) {
      $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($case.s))
      $p = Start-Process powershell.exe -Credential $ProbeCredential -LoadUserProfile -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-EncodedCommand', $enc
      # for the file read the directory listing itself is denied (5) or, if listing leaked, the read must be
      Check ($p.ExitCode -eq 5) "non-administrator user cannot $($case.n) (probe exit $($p.ExitCode); 5 = access denied)"
    }
  } finally { Remove-Item Env:ADIQ_PROBE_PATH -ErrorAction SilentlyContinue }
} else {
  "skipped: behavioural probe (no -ProbeCredential)"
}
# Hardening cases (run by the lab after Set-ApiTlsDirAcl.ps1; tracked by T-0409):
#   - a directory pre-created by a non-admin user is refused (Set-ApiTlsDirAcl.ps1 throws, owner check);
#   - a junction child is refused and its target's ACL is unchanged;
#   - files inside end up owned by Administrators.
Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
  $o = (Get-Acl -LiteralPath $_.FullName).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  Check ($o -eq 'S-1-5-32-544') "file $($_.Name) is owned by Administrators"
}
if ($fail) { exit 1 }
