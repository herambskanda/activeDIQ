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
  $p = Start-Process powershell.exe -Credential $ProbeCredential -LoadUserProfile -Wait -PassThru -WindowStyle Hidden `
    -ArgumentList '-NoProfile', '-Command', "try { Get-ChildItem -LiteralPath '$Path' -ErrorAction Stop | Out-Null; exit 0 } catch [System.UnauthorizedAccessException] { exit 5 } catch { exit 9 }"
  Check ($p.ExitCode -eq 5) "non-administrator user is denied (probe exit $($p.ExitCode); 5 = access denied)"
} else {
  "skipped: behavioural probe (no -ProbeCredential)"
}
if ($fail) { exit 1 }
