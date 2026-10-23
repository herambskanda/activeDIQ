# fs1: wait for the domain, join it, create a file share (SMB audit target), enable WinRM over HTTPS.
. C:\lab\common.ps1
$c = Get-LabConfig
switch (Get-Stage) {
  'start' {
    for ($i = 0; $i -lt 90; $i++) { if (Resolve-DnsName $c.domain -Server $c.dcIp -ErrorAction SilentlyContinue) { break }; Start-Sleep 30 }
    $cred = New-Object pscredential("$($c.netbios)\Administrator", (ConvertTo-Secure $c.adminPassword))
    Set-Stage 'joined'
    Add-Computer -DomainName $c.domain -Credential $cred -Restart -Force
  }
  'joined' {
    Install-WindowsFeature FS-FileServer, RSAT-AD-PowerShell | Out-Null
    New-Item -ItemType Directory -Force C:\Shares\Lab | Out-Null
    if (-not (Get-SmbShare Lab -ErrorAction SilentlyContinue)) { New-SmbShare -Name Lab -Path C:\Shares\Lab -FullAccess "$($c.netbios)\Domain Admins" | Out-Null }
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null          # 5140/5145
    auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null         # 4663
    $cert = New-SelfSignedCertificate -DnsName "fs1.$($c.domain)" -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Get-WSManInstance winrm/config/Listener -Enumerate | ? Transport -eq HTTPS | Remove-WSManInstance -ErrorAction SilentlyContinue
    New-WSManInstance winrm/config/Listener -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } -ValueSet @{ Hostname = "fs1.$($c.domain)"; CertificateThumbprint = $cert.Thumbprint } | Out-Null
    New-NetFirewallRule -DisplayName 'Lab WinRM HTTPS' -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Set-Stage 'done'; Write-LabLog 'fs1 provisioned'; Remove-LabSecrets
    Unregister-ScheduledTask LabResume -Confirm:$false -ErrorAction SilentlyContinue
  }
}
