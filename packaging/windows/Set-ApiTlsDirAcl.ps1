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

$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$trustedOwners = @($admins.Value, $system.Value, $svc.Value)

# The parent must not let an unprivileged principal create, write or delete children: otherwise a local
# user can pre-create the directory (and own it) or swap a path component between check and use.
$safeWriters = @($admins.Value, $system.Value, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')  # + TrustedInstaller, CREATOR OWNER
# Write-type rights plus the raw generic bits (GENERIC_ALL 0x10000000, GENERIC_WRITE 0x40000000,
# MAXIMUM_ALLOWED 0x02000000): an ACE can carry them unmapped and they would otherwise AND to zero.
$dangerMask = [int][System.Security.AccessControl.FileSystemRights]'CreateFiles,CreateDirectories,WriteData,AppendData,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership,WriteAttributes,WriteExtendedAttributes' -bor 0x52000000
function Assert-NoUnprivilegedWrite([string]$Target, [string[]]$AllowedSids) {
  foreach ($r in (Get-Acl -LiteralPath $Target).Access) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    $sidv = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($AllowedSids -contains $sidv) { continue }
    if (([int]$r.FileSystemRights -band $dangerMask) -ne 0) { throw "'$Target' grants write access to $sidv; refusing. Use a protected location (Administrators/SYSTEM only) and retry." }
  }
}
$parent = Split-Path -Parent -Path $Path
if (-not $parent -or -not (Test-Path -LiteralPath $parent)) { throw "Parent of '$Path' does not exist; create a protected parent first." }
Assert-NoUnprivilegedWrite $parent $safeWriters

if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
$item = Get-Item -LiteralPath $Path -Force
if (-not $item.PSIsContainer) { throw "'$Path' is not a directory." }
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "'$Path' is a reparse point (symlink/junction); refusing to ACL it." }
$owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($trustedOwners -notcontains $owner) { throw "'$Path' is owned by $owner, not Administrators, SYSTEM or the service identity; refusing to adopt it." }
# An existing directory's own DACL is checked too: an Administrators-owned folder that lets Users write
# would let them hold a handle opened before the ACL is replaced.
Assert-NoUnprivilegedWrite $Path ($safeWriters + $svc.Value)

# apitls is a flat layout: no recursion. Refuse anything that is not a plain single-link file, so
# nothing planted by a lower-privileged user (junction, symlink, subdirectory, hardlink) is followed.
$entries = @(Get-ChildItem -LiteralPath $Path -Force)
foreach ($e in $entries) {
  if ($e.PSIsContainer) { throw "'$($e.FullName)' is a subdirectory; the TLS directory is flat. Remove it." }
  if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "'$($e.FullName)' is a reparse point; refusing to follow it." }
  $out = @(& fsutil.exe hardlink list $e.FullName)
  if ($LASTEXITCODE -ne 0) { throw "fsutil hardlink list failed for '$($e.FullName)' (exit $LASTEXITCODE): $out" }
  $links = $out.Count
  if ($links -gt 1) { throw "'$($e.FullName)' has $links hard links; refusing." }
}

$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)   # protected, inherited entries dropped
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @($admins, $svc)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', $inherit, 'None', 'Allow')))
}
Set-Acl -LiteralPath $Path -AclObject $acl

# Files already inside (an upgrade): owner Administrators (an owner keeps implicit WRITE_DAC), inheritance
# on, explicit entries dropped, so the directory ACL alone governs them.
foreach ($e in $entries) {
  $a = Get-Acl -LiteralPath $e.FullName
  $a.SetOwner($admins)
  $a.SetAccessRuleProtection($false, $false)
  $a.Access | Where-Object { -not $_.IsInherited } | ForEach-Object { [void]$a.RemoveAccessRuleSpecific($_) }
  Set-Acl -LiteralPath $e.FullName -AclObject $a
}
Write-Output "ACL set on ${Path}: Administrators and $($svc.Value) only"
