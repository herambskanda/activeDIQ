<#
 First-run setup secret, Windows side (T-0635, TM-TB16-T7, TM-TB1-T2). Writes a fresh random secret to a file
 only the installing administrator (and SYSTEM, which the server service needs only if it runs as SYSTEM; it
 does not, so SYSTEM is omitted) can read, with an expiry the server enforces. The server (T-0636) reads the
 file, compares in constant time, deletes it on first successful use and refuses it after ExpiresUtc; this
 script never stores the secret anywhere else and never logs it.

 Format of the file, two lines: the secret (43 chars, base64url of 32 random bytes), then ExpiresUtc
 (ISO 8601, UTC). Result ACL: inheritance off, owner and sole ACE = -AdministratorSid (FullControl) plus the
 service identity read+delete when -ServiceSid is given. Not Everyone, not Users, not Administrators as a group
 (any other administrator is not "the installing administrator").
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Path,
  [Parameter(Mandatory)][string]$AdministratorSid,
  [string]$ServiceSid,
  [ValidateRange(5, 1440)][int]$LifetimeMinutes = 60
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-32-544', 'S-1-5-7')
foreach ($s in @($AdministratorSid, $ServiceSid)) {
  if ($s -and $s -notmatch '^S-1-\d+(-\d+)+$') { throw "not a SID: $s" }
  if ($s -and ($broad -contains $s)) { throw "SID $s is a broad group; use the installing user's own SID" }
}
if (Test-Path -LiteralPath $Path) { throw "refusing to overwrite an existing setup secret: $Path" }
$dir = Split-Path -Parent $Path
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "directory does not exist: $dir" }

$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
[Array]::Clear($bytes, 0, $bytes.Length)
$expires = [DateTime]::UtcNow.AddMinutes($LifetimeMinutes).ToString('o')

# Create the file with the final protected DACL already in place (no window where it is readable).
$sec = New-Object System.Security.AccessControl.FileSecurity
$sec.SetAccessRuleProtection($true, $false)
$admin = New-Object System.Security.Principal.SecurityIdentifier($AdministratorSid)
$sec.SetOwner($admin)
$sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')))
if ($ServiceSid) {
  $svc = New-Object System.Security.Principal.SecurityIdentifier($ServiceSid)
  $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($svc, 'Read, Delete', 'Allow')))
}
$fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.Security.AccessControl.FileSystemRights]'WriteData, ReadPermissions, ChangePermissions, TakeOwnership', [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, $sec)
try {
  $w = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
  $w.Write($secret + "`n" + $expires + "`n")
  $w.Flush()
} finally { $fs.Dispose() }
$secret = $null
Write-Output "Setup secret written to $Path (expires $expires). Read it as the installing administrator; it works once."
