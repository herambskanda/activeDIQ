<#
 Creates ACTIVEDIQ_API_TLS_DIR and locks it to the service identity and Administrators (T-0104,
 TM-TB16-T3). Go's 0600/0700 modes do nothing on Windows, so the ACL is the only access control on the
 API's private key. Called by the MSI custom action (after the service identity exists) and by the
 upgrade path; it is idempotent and replaces whatever ACL the directory had.
 Result: inheritance off with no inherited entries copied, owner Administrators, FullControl for
 Administrators (S-1-5-32-544) and the service identity only. Nobody else, no broad
 group and not SYSTEM.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Path,
  [Parameter(Mandatory)][string]$ServiceIdentity   # DOMAIN\gmsa$ (or a SID string)
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
if ($ServiceIdentity -match '^S-1-\d+(-\d+)+$') {
  $svc = New-Object System.Security.Principal.SecurityIdentifier($ServiceIdentity)
} else {
  $svc = (New-Object System.Security.Principal.NTAccount($ServiceIdentity)).Translate([System.Security.Principal.SecurityIdentifier])
}
# Refuse identities that would reopen the directory to everyone.
$broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-7')
if ($broad -contains $svc.Value) { throw "ServiceIdentity '$ServiceIdentity' is a broad group ($($svc.Value)); use the service's own account." }

if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
$item = Get-Item -LiteralPath $Path -Force
if (-not $item.PSIsContainer) { throw "'$Path' is not a directory." }
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "'$Path' is a reparse point (symlink/junction); refusing to ACL it." }

$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)   # protected, inherited entries dropped
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @($admins, $svc)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', $inherit, 'None', 'Allow')))
}
Set-Acl -LiteralPath $Path -AclObject $acl

# Files already inside (an upgrade) must not keep their own explicit entries or protected state.
Get-ChildItem -LiteralPath $Path -Recurse -Force | ForEach-Object {
  $a = Get-Acl -LiteralPath $_.FullName
  $a.SetAccessRuleProtection($false, $false)
  $a.Access | Where-Object { -not $_.IsInherited } | ForEach-Object { [void]$a.RemoveAccessRuleSpecific($_) }
  Set-Acl -LiteralPath $_.FullName -AclObject $a
}
Write-Output "ACL set on $Path: Administrators and $($svc.Value) only"
