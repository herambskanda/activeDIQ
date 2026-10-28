# dc1: promote to a new forest, then LDAPS cert, service account + delegation, audit/NTLM GPOs, snapshot-ready.
. C:\lab\common.ps1
$c = Get-LabConfig
$LabDir = 'C:\lab'
switch (Get-Stage) {
  'start' {
    $feat = Install-WindowsFeature AD-Domain-Services, DNS, GPMC, RSAT-AD-Tools, RSAT-AD-PowerShell -IncludeManagementTools
    # ADCS is deliberately NOT installed here: Install-ADDSForest refuses while Certificate Server is installed (T-0496)
    # Windows refuses Install-ADDSForest while a restart from the role install is pending (T-0496): reboot and resume
    # at 'start'. One reboot only (marker file), so a flag that never clears cannot loop; the stage stays 'start'.
    if ($feat.RestartNeeded -ne 'No' -and -not (Test-Path "$LabDir\feature-reboot")) {
      Set-Content "$LabDir\feature-reboot" (Get-Date -Format o)
      Write-LabLog "features installed, RestartNeeded=$($feat.RestartNeeded): restarting, will resume at stage start"
      Restart-Computer -Force
      return
    }
    # forest/domain functional level WinThreshold (2016) is the highest; 2025 level needs a feature-level raise below.
    # -NoRebootOnCompletion so the stage is recorded only after promotion succeeded, then we reboot ourselves.
    Install-ADDSForest -DomainName $c.domain -DomainNetbiosName $c.netbios -SafeModeAdministratorPassword (ConvertTo-Secure $c.dsrmPassword) `
      -InstallDns -NoRebootOnCompletion -Force | Out-Null
    Set-Stage 'promoted'
    Restart-Computer -Force
  }
  'promoted' {
    Import-Module ActiveDirectory
    for ($i = 0; $i -lt 30; $i++) { try { Get-ADDomain | Out-Null; break } catch { Start-Sleep 20 } }
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    # enterprise root CA, so the DC gets a CA-issued LDAPS certificate (Domain Controller template) by autoenrolment
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CaCommonName 'activeDIQ Lab Root CA' -KeyLength 3072 `
      -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -Force | Out-Null
    Set-Stage 'configure'
  }
  'configure' {
    Import-Module ActiveDirectory
    $base = $c.baseDn
    New-ADOrganizationalUnit -Name Managed -Path $base -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name ServiceAccounts -Path $base -ErrorAction SilentlyContinue
    New-ADUser -Name svc-activediq -SamAccountName svc-activediq -UserPrincipalName "svc-activediq@$($c.domain)" `
      -Path "OU=ServiceAccounts,$base" -AccountPassword (ConvertTo-Secure $c.svcPassword) -Enabled $true -PasswordNeverExpires $true
    # delegation on OU=Managed only (never Domain Admins): users/groups/computers create-delete + full property control
    $sid = (Get-ADUser svc-activediq).SID.Value
    foreach ($cls in 'user', 'group', 'computer', 'organizationalUnit') {
      & dsacls "OU=Managed,$base" /I:T /G "${sid}:CCDC;$cls" | Out-Null
    }
    & dsacls "OU=Managed,$base" /I:S /G "${sid}:GA;;user" "${sid}:RPWP;;user" "${sid}:RPWP;;group" "${sid}:RPWP;;computer" | Out-Null
    New-ADUser -Name 'lab-user-01' -SamAccountName lab-user-01 -Path "OU=Managed,$base" -AccountPassword (ConvertTo-Secure $c.userPassword) -Enabled $true
    # Recycle Bin and a UPN suffix for Entra Connect readiness
    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $c.domain -Confirm:$false -ErrorAction SilentlyContinue
    & C:\lab\audit-gpo.ps1
    & C:\lab\entra-ready.ps1
    # LDAPS: trigger autoenrolment now and require a server certificate on 636
    certutil -pulse | Out-Null; gpupdate /force | Out-Null
    for ($i = 0; $i -lt 30; $i++) { if (Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -like '*dc1*' }) { break }; Start-Sleep 20 }
    Set-Stage 'done'; Write-LabLog 'dc1 provisioned'; Remove-LabSecrets
    Unregister-ScheduledTask LabResume -Confirm:$false -ErrorAction SilentlyContinue
  }
}
