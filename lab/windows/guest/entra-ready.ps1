# Entra Connect readiness for G9 (does Entra password reset + writeback reach an AD account in a protected group).
# Does NOT install Entra Connect: that needs a tenant Global Admin (CEO, device-code style) and runs on fs1 later.
# Prepares everything on the AD side and writes C:\lab\entra-ready.txt for the runbook.
. C:\lab\common.ps1
Import-Module ActiveDirectory
$c = Get-LabContext   # works with or without lab.json (deleted after provisioning)
$base = $c.baseDn
New-ADOrganizationalUnit -Name EntraSync -Path "OU=Managed,$base" -ErrorAction SilentlyContinue
# a routable UPN suffix is needed to match the Entra tenant domain: set via env when the tenant exists
Set-ADForest -Identity $c.domain -UPNSuffixes @{ Add = 'lab.activediq.example' } -ErrorAction SilentlyContinue
# svc-entra-connect: the AD DS Connector account (Entra Connect creates its own MSOL_ account in express mode)
foreach ($n in 'g9-standard', 'g9-protected') {
  if (-not (Get-ADUser -Filter "SamAccountName -eq '$n'")) {
    if (-not $c.userPassword) { throw "$n is missing and lab.json (password source) is gone; reset the VM to the clean snapshot and re-provision" }
    New-ADUser -Name $n -SamAccountName $n -UserPrincipalName "$n@lab.activediq.example" -Path "OU=EntraSync,OU=Managed,$base" `
      -AccountPassword (ConvertTo-Secure $c.userPassword) -Enabled $true
  }
}
Add-ADGroupMember 'Account Operators' g9-protected -ErrorAction SilentlyContinue   # AdminSDHolder-protected: the G9 subject
$r = @("domain=$($c.domain)", "forestMode=$((Get-ADForest).ForestMode)", "recycleBin=$(@(Get-ADOptionalFeature 'Recycle Bin Feature').EnabledScopes.Count -gt 0)",
       'syncOU=OU=EntraSync,OU=Managed', 'g9Users=g9-standard,g9-protected', 'entraConnectInstalled=false (needs tenant; see runbook)')
$r | Set-Content C:\lab\entra-ready.txt
Write-LabLog 'entra readiness prepared'
