# AES256 keytab for the lab service account svc-activediq (T-1267), so the lab server binds like the shipping connector
# (SASL GSSAPI + channel binding). Run on dc1 as Administrator by `gssapi-lab keytab`; the password arrives in $env:SVC_PW
# (the account's EXISTING password: ktpass re-sets it to the same value, so password binds of other proofs keep working;
# it only bumps the kvno). Output: C:\lab\gssapi\svc-activediq.keytab (the caller fetches and deletes it).
. C:\lab\common.ps1
Import-Module ActiveDirectory
$d = Get-ADDomain
$realm = $d.DNSRoot.ToUpper()
$name = 'svc-activediq'
if (-not $env:SVC_PW) { throw 'svc-keytab: SVC_PW not set' }
if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'")) { throw "svc-keytab: $name does not exist on dc1" }
$out = 'C:\lab\gssapi'
New-Item -ItemType Directory -Force $out | Out-Null
Set-ADUser $name -KerberosEncryptionType AES128, AES256
Remove-Item "$out\svc-activediq.keytab" -ErrorAction SilentlyContinue
$ErrorActionPreference = 'Continue'
$null = & ktpass /princ "$name@$realm" /mapuser "$($d.NetBIOSName)\$name" /pass $env:SVC_PW /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out "$out\svc-activediq.keytab" +setupn 2>&1
$ErrorActionPreference = 'Stop'
if (-not (Test-Path "$out\svc-activediq.keytab")) { throw 'svc-keytab: ktpass produced no keytab' }
icacls $out /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
Write-LabLog "svc-keytab: $name keytab written to $out"
