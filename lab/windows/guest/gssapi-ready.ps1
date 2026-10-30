# SASL GSSAPI + channel binding readiness for dc1 (T-0566). Idempotent; run on dc1 as Administrator.
# Effects are [UNVERIFIED] until the first real lab run (runbook windows-lab.md section 11).
#  1. LDAP signing required (LDAPServerIntegrity=2) and channel binding always (LdapEnforceChannelBindingTokens=2)
#     on the DC (https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a).
#  2. svc-t0566-gssapi: a user account, AES-only, with an AES keytab from ktpass.
#  3. gmsa-t0566$: a gMSA, AES-only; its current managed-password blob is exported so the Go test can derive the keytab.
# Output (copy to the lab host, delete from the VM; never email): C:\lab\gssapi\svc.keytab, C:\lab\gssapi\gmsa.json
. C:\lab\common.ps1
Import-Module ActiveDirectory
$d = Get-ADDomain
$realm = $d.DNSRoot.ToUpper()
$out = 'C:\lab\gssapi'
New-Item -ItemType Directory -Force $out | Out-Null

$ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$changed = $false
foreach ($kv in @(@('LDAPServerIntegrity', 2), @('LdapEnforceChannelBindingTokens', 2))) {
  $cur = (Get-ItemProperty $ntds -Name $kv[0] -ErrorAction SilentlyContinue).($kv[0])
  if ($cur -ne $kv[1]) { Set-ItemProperty $ntds -Name $kv[0] -Type DWord -Value $kv[1]; $changed = $true }
}
if ($changed) { Write-LabLog 'gssapi: LDAP signing/channel binding policy set; REBOOT dc1 (or restart NTDS) before testing' }

# service account with a keytab
$name = 'svc-t0566-gssapi'
$pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ }) + 'Aa1!'
if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'")) {
  New-ADUser -Name $name -SamAccountName $name -Path "OU=ServiceAccounts,$($d.DistinguishedName)" `
    -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
}
Set-ADUser $name -KerberosEncryptionType AES128, AES256 -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
Remove-Item "$out\svc.keytab" -ErrorAction SilentlyContinue
# ktpass resets the account password to $pw and writes AES256 keys; -ptype NT_PRINCIPAL so the principal is the plain account name
& ktpass /princ "$name@$realm" /mapuser "$($d.NetBIOSName)\$name" /pass $pw /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out "$out\svc.keytab" +setupn | Out-Null
if (-not (Test-Path "$out\svc.keytab")) { throw 'ktpass produced no keytab' }

# gMSA (KDS root key backdated 10 h so it is usable at once in a lab)
if (-not (Get-KdsRootKey)) { Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10) | Out-Null }
$g = 'gmsa-t0566'
if (-not (Get-ADServiceAccount -Filter "Name -eq '$g'")) {
  New-ADServiceAccount -Name $g -DNSHostName "$g.$($d.DNSRoot)" -KerberosEncryptionType AES128, AES256 `
    -PrincipalsAllowedToRetrieveManagedPassword "$env:COMPUTERNAME$" -Path "OU=ServiceAccounts,$($d.DistinguishedName)"
}
$acct = Get-ADServiceAccount $g -Properties 'msDS-ManagedPassword', 'msDS-KeyVersionNumber'
[pscustomobject]@{
  principal = "$g`$"; realm = $realm; dnsHostName = "$g.$($d.DNSRoot)"
  kvno = [int]$acct.'msDS-KeyVersionNumber'
  blob = [Convert]::ToBase64String([byte[]]$acct.'msDS-ManagedPassword')
} | ConvertTo-Json | Set-Content "$out\gmsa.json"
icacls $out /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
Write-LabLog 'gssapi: svc-t0566-gssapi keytab and gmsa-t0566 blob exported to C:\lab\gssapi'
