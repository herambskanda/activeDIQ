# dc2: promote to a CHILD domain of the lab forest (child.win.activediq.test, NetBIOS WINCHILD, DNS delegation), T-1233.
# Staged and reboot-safe like dc.ps1; reached through boot.ps1 (role 'child-dc'). Human-only: A-0025 covers dc1, not dc2.
# Secrets: the parent Administrator password is read ONLY here, as a SecureString prompt, held in memory for the one
# Install-ADDSDomain call and never written, logged, echoed or passed in argv. The DSRM password is generated at
# promotion into an ACL'd file (SYSTEM + Administrators) that is locked BEFORE the secret is written. Nothing logs either.
. C:\lab\common.ps1
$c = Get-LabConfig
$LabDir = 'C:\lab'
$childFqdn = "$($c.childName).$($c.domain)"
$dsrmFile = "$LabDir\dsrm-password.txt"
switch (Get-Stage) {
  'start' {
    $feat = Install-WindowsFeature AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-AD-PowerShell -IncludeManagementTools
    # same pending-restart rule as dc.ps1 (T-0496): reboot once (marker file), resume at 'start'
    if ($feat.RestartNeeded -ne 'No' -and -not (Test-Path "$LabDir\feature-reboot")) {
      Set-Content "$LabDir\feature-reboot" (Get-Date -Format o)
      Write-LabLog "features installed, RestartNeeded=$($feat.RestartNeeded): restarting, will resume at stage start"
      Restart-Computer -Force
      return
    }
    # The LabResume task runs headless as SYSTEM and cannot prompt. Only a human at a console may continue.
    if (-not [Environment]::UserInteractive) {
      Write-LabLog "waiting for a human: run C:\lab\boot.ps1 in an elevated console on DC2 (prompts for the parent Administrator password)"
      return
    }
    $parentPw = Read-Host -AsSecureString "Password of $($c.netbios)\Administrator (parent domain $($c.domain))"
    $cred = New-Object pscredential("$($c.netbios)\Administrator", $parentPw)
    if (-not (Test-Path $dsrmFile)) {   # lock the (empty) file first, then write the secret into it
      New-Item -ItemType File $dsrmFile | Out-Null
      Protect-LabFile $dsrmFile
      Set-Content $dsrmFile (New-LabPassword) -Encoding ascii
      Write-LabLog "DSRM password generated into $dsrmFile (SYSTEM + Administrators only)"
    }
    $dsrm = ConvertTo-Secure ((Get-Content $dsrmFile -Raw).Trim())
    # -NoRebootOnCompletion so the stage is recorded only after promotion succeeded, then we reboot ourselves.
    # -CreateDnsDelegation creates the child's delegation in the parent zone on dc1. -NoGlobalCatalog: dc1 stays the only GC;
    # as a GC it holds the child's partial NC regardless (T-0786 dials dc1:3269, so the test target is unchanged).
    Install-ADDSDomain -DomainType ChildDomain -NewDomainName $c.childName -ParentDomainName $c.domain `
      -NewDomainNetbiosName $c.childNetbios -Credential $cred -SafeModeAdministratorPassword $dsrm `
      -InstallDns -CreateDnsDelegation -NoGlobalCatalog -NoRebootOnCompletion -Force | Out-Null
    Set-Stage 'promoted'
    Restart-Computer -Force
  }
  'promoted' {
    Import-Module ActiveDirectory
    for ($i = 0; $i -lt 30; $i++) { try { Get-ADDomain | Out-Null; break } catch { Start-Sleep 20 } }
    if ((Get-ADDomain).DNSRoot -ne $childFqdn) { throw "promoted domain is '$((Get-ADDomain).DNSRoot)', expected $childFqdn" }
    Set-Stage 'done'; Write-LabLog "dc2 provisioned ($childFqdn); dsrm file kept at $dsrmFile until a human moves it"; Remove-LabSecrets
    Unregister-ScheduledTask LabResume -Confirm:$false -ErrorAction SilentlyContinue
  }
}
