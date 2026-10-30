# GPO / audit-policy hooks the Windows-only proofs need (T-0256 et al). Idempotent. Runs on dc1.
# Effects are [UNVERIFIED] until the first real lab run records the events in the runbook.
. C:\lab\common.ps1
Import-Module GroupPolicy
Import-Module ActiveDirectory
$c = Get-LabContext   # works with or without lab.json (deleted after provisioning)
$gpo = 'Lab - DC audit and NTLM'
if (-not (Get-GPO -Name $gpo -ErrorAction SilentlyContinue)) { New-GPO -Name $gpo | Out-Null }
New-GPLink -Name $gpo -Target "OU=Domain Controllers,$($c.baseDn)" -ErrorAction SilentlyContinue | Out-Null
# Advanced audit policy via audit.csv would be machine-local; instead force it with the SCENoApplyLegacyAuditPolicy
# switch and set subcategories directly on dc1 with auditpol (applied by this script and re-applied at boot).
Set-GPRegistryValue -Name $gpo -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName SCENoApplyLegacyAuditPolicy -Type DWord -Value 1 | Out-Null
$subs = 'Credential Validation',            # 4776 (NTLM validation at the DC)
        'Kerberos Authentication Service', 'Kerberos Service Ticket Operations', # 4768/4769
        'Logon', 'Account Lockout',         # 4624/4625/4740
        'User Account Management', 'Security Group Management', 'Computer Account Management', # 4720/4738/4728...
        'Directory Service Changes', 'Directory Service Access' # 5136/4662
foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
# NTLM: audit (not block) everywhere, so events 8001-8004 appear in Microsoft-Windows-NTLM/Operational
#   8001 outgoing NTLM audit, 8002 incoming NTLM audit, 8003 in-domain NTLM audit, 8004 NTLM auth at the DC.
$msv = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
Set-GPRegistryValue -Name $gpo -Key $msv -ValueName AuditReceivingNTLMTraffic -Type DWord -Value 2 | Out-Null   # audit all incoming
Set-GPRegistryValue -Name $gpo -Key $msv -ValueName RestrictSendingNTLMTraffic -Type DWord -Value 1 | Out-Null  # audit all outgoing
Set-GPRegistryValue -Name $gpo -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName AuditNTLMInDomain -Type DWord -Value 7 | Out-Null
# Restriction switch kept OFF by default; a test flips it with this GPO value to 2 (deny all) and reverts via lab-reset:
#   Set-GPRegistryValue -Name 'Lab - DC audit and NTLM' -Key $msv -ValueName RestrictNTLMInDomain -Type DWord -Value <n>
wevtutil sl 'Microsoft-Windows-NTLM/Operational' /e:true | Out-Null
wevtutil sl Security /ms:536870912 | Out-Null   # 512 MB security log so a large audit run is not overwritten
Write-LabLog 'audit and NTLM GPO applied'
