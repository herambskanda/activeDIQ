# Lab cases for T-0557 (ADR-0006 verification items and contract section 5 resource bounds). Runs ON the lab DC as an
# elevated Administrator, through lab/windows/bin/agent-verify --guest agent-t0557.ps1 (which builds and uploads the
# MSI and the test binaries, and holds the dc1 lock). Prints "CASE <id> PASS|FAIL <detail>", "INFO ..." and the
# "LAB ..." measurement lines of the Go lab tests. It installs and removes the agent, creates and removes one lab
# user and one GPO, clears nothing but its own files, and restores the Security log size. Lab DC only.
#
# What it adds to agent-verify.ps1 (T-0648): a REAL Group Policy object that sets the Security log's ChannelAccess
# (T-0648 only simulated "a GPO reset" with wevtutil), the refusal of a token that holds extra privileges, and the
# resource bounds of section 5 measured on a DC under a Security-event load with logon latency before and during.
param([string]$Build = 'C:\lab\build', [string]$Version = '0.0.1', [int]$LoadSeconds = 60, [int[]]$Threads = @(8, 24), [ValidateSet('full', 'gpo-restart')][string]$Mode = 'full')
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Msi = Join-Path $Build "activediq-agent-$Version.msi"
$Setup = 'C:\Program Files\skenzeriq\agent\agentsetup.exe'
$AgentExe = 'C:\Program Files\skenzeriq\agent\activediq-agent.exe'
$Svc = 'activeDIQAgent'
$SvcAcct = 'NT SERVICE\activeDIQAgent'
$DataRoot = Join-Path $env:ProgramData 'skenzeriq'
$Out = 'C:\lab\out'
$GpoName = 'T0557-SecurityLogAccess'
$PolKey = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security'
$PolKeyPs = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
$script:fail = 0

function Case($id, [bool]$ok, $detail) {
    if (-not $ok) { $script:fail++ }
    "CASE $id $(if ($ok) { 'PASS' } else { 'FAIL' }) $detail"
}
function MsiRun($args_, $log) { (Start-Process msiexec -ArgumentList "$args_ /qn /l*v `"$Build\$log`"" -Wait -PassThru).ExitCode }
function ChannelSddl { (wevtutil gl Security | Select-String 'channelAccess:').Line -replace '^\s*channelAccess:\s*', '' }
function SvcSidString { try { (New-Object Security.Principal.NTAccount($SvcAcct)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null } }
function HasAce { $sid = SvcSidString; [bool]($sid -and ((ChannelSddl) -like "*;;;$sid)*")) }
function PolicyValue { (Get-ItemProperty $PolKeyPs -ErrorAction SilentlyContinue).ChannelAccess }
function Uninstall {
    foreach ($k in Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'activeDIQ Agent') {
        [void](MsiRun "/x $($k.PSChildName)" 'uninstall.log')
    }
}
function Remove-DataRoot {
    if (Test-Path $DataRoot) {
        if ((Get-Item $DataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { (Get-Item $DataRoot -Force).Delete() }
        else { Remove-Item -Recurse -Force $DataRoot }
    }
}
function Reset-Host { Uninstall; if (Get-Service $Svc -ErrorAction SilentlyContinue) { sc.exe delete $Svc | Out-Null }; Remove-DataRoot }

# Run a program as the agent's own identity (same technique as agent-verify.ps1): the service image is pointed at it
# for a moment and SCM starts it with the real restricted service token.
function RunAsService($imagePath, $doneFile, $waitSec = 20) {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc"
    if (-not (Test-Path $k)) { return $null }
    if ($doneFile) { Remove-Item $doneFile -ErrorAction SilentlyContinue }
    icacls $Out /grant "${SvcAcct}:(OI)(CI)(M)" | Out-Null
    $orig = (Get-ItemProperty $k).ImagePath
    Stop-Service $Svc -ErrorAction SilentlyContinue
    Set-ItemProperty $k ImagePath $imagePath
    try {
        Start-Process sc.exe -ArgumentList "start $Svc" -WindowStyle Hidden
        for ($i = 0; $i -lt ($waitSec * 2); $i++) { Start-Sleep -Milliseconds 500; if ($doneFile -and (Test-Path $doneFile)) { Start-Sleep -Milliseconds 500; break } }
    } finally { Stop-Service $Svc -ErrorAction SilentlyContinue; Set-ItemProperty $k ImagePath $orig }
    if ($doneFile) { if (Test-Path $doneFile) { (Get-Content $doneFile -Raw).Trim() } else { $null } }
}
function ServiceReadSecurity { RunAsService "`"$Build\agent.test.exe`" -test.run=TestLabReadAsService -labout=$Out\svc-read.txt" "$Out\svc-read.txt" }

# Poll the three observables after a policy change: the policy value, the channel configuration the Event Log
# service reports, and whether the service identity can really subscribe. Returns seconds until the service
# identity's result equals $want, or -1 after $maxSec.
function WaitForRead($want, $maxSec) {
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $maxSec) {
        $r = ServiceReadSecurity
        if (($want -eq 'readable' -and $r -like 'readable*') -or ($want -eq 'unreadable' -and $r -eq 'unreadable')) { return [int]((Get-Date) - $t0).TotalSeconds }
        Start-Sleep -Seconds 3
    }
    -1
}
function Snap($label) {
    $p = PolicyValue
    "INFO $label policy.ChannelAccess=$(if ($p) { $p } else { '<absent>' })"
    "INFO $label wevtutil.channelAccess=$(ChannelSddl)"
}

New-Item -ItemType Directory -Force $Out | Out-Null
Reset-Host
$origMax = ((wevtutil gl Security | Select-String 'maxSize:').Line -replace '^\s*maxSize:\s*', '').Trim()
$stock = ChannelSddl
"INFO os: $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber); logical processors $((Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors); RAM MiB $([int]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB))"
"INFO Security maxSize before: $origMax; baseline channelAccess: $stock"
Case 'T0-clean' ($stock -notlike '*S-1-5-80-*' -and -not (PolicyValue)) 'no service-SID ACE and no log-access policy before the run'

$rc = MsiRun "/i `"$Msi`"" 'install.log'
Case 'I1-install' ($rc -eq 0 -and (HasAce)) "msiexec exit $rc; service-SID ACE in Security channelAccess: $(HasAce)"
$aceSddl = ChannelSddl
$res = ServiceReadSecurity
Case 'I2-readable-as-service' ($res -like 'readable events=*') "Security read as $SvcAcct through the agent's event source: $res"

# ---------------------------------------------------------------------------------------------------------------
# Token privileges: the agent started with a token that holds more than SeChangeNotify refuses before it opens a
# subscription (ADR-0006 decision 3, fitness A2). An elevated administrator console holds SeDebug, SeBackup, ... .
$o = & $AgentExe 2>&1 | Out-String
$rcAgent = $LASTEXITCODE
"INFO elevated-admin run output: $($o.Trim() -replace '\s+', ' ')"
Case 'P1-admin-token-refused' ($rcAgent -ne 0 -and $o -match 'privilege') "activediq-agent.exe from an elevated administrator token exited $rcAgent"
Case 'P2-refusal-names-extras' ($o -match 'SeDebugPrivilege' -and $o -match 'SeBackupPrivilege') 'the refusal names the extra privileges'
$whoami = (whoami /priv | Out-String)
"INFO admin token privileges (for contrast): $((($whoami -split "`n" | Select-String '^Se') | ForEach-Object { ($_ -split '\s+')[0] }) -join ' ')"

# ---------------------------------------------------------------------------------------------------------------
# A REAL Group Policy object. Policy "Configure log access" is Administrative Templates > Windows Components >
# Event Log Service > Security > Configure log access; it writes ChannelAccess under
# HKLM\Software\Policies\Microsoft\Windows\EventLog\Security.
Import-Module GroupPolicy -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$dcOu = (Get-ADDomain).DomainControllersContainer
Get-GPO -Name $GpoName -ErrorAction SilentlyContinue | Remove-GPO -ErrorAction SilentlyContinue
# ---------------------------------------------------------------------------------------------------------------
# Mode gpo-restart: the live GPO above did not change the effective access. Does it apply when the Event Log service
# restarts (which is what a reboot does)? The Event Log service is restarted with its running dependents recorded
# first and started again afterwards; the DC services are checked at the end.
if ($Mode -eq 'gpo-restart') {
    function RestartEventLog {
        $dep = @(Get-Service EventLog | Select-Object -ExpandProperty DependentServices | Where-Object Status -eq 'Running' | ForEach-Object Name)
        "INFO running dependents of EventLog: $($dep -join ' ')"
        net stop eventlog /y | Out-Null
        Start-Sleep 2
        Start-Service EventLog
        foreach ($d in $dep) { Start-Service $d -ErrorAction SilentlyContinue }
        Start-Sleep 5
    }
    try {
        $gpo = New-GPO -Name $GpoName -Comment 'T-0557 lab; removed at the end of the run'
        [void](Set-GPRegistryValue -Name $GpoName -Key $PolKey -ValueName ChannelAccess -Type String -Value $stock)
        [void](New-GPLink -Name $GpoName -Target $dcOu -LinkEnabled Yes)
        [void](gpupdate /force /target:computer 2>&1)
        $before = ServiceReadSecurity
        "INFO before the Event Log service restarts, with the GPO applied: service identity read = $before"
        RestartEventLog
        Snap 'after-eventlog-restart-with-gpo-lacking-sid'
        $after = ServiceReadSecurity
        Case 'G7-restart-applies-policy' ($after -eq 'unreadable') "after the Event Log service restarts with the GPO in force: service identity read = $after (before the restart: $before); config ACE kept: $(HasAce)"
        Case 'G7-nonadmin-sd-is-the-policy' ((ChannelSddl) -eq $stock) 'wevtutil gl Security now reports the policy SDDL, not the MSI one'
        # agent-side signal: what the product sees
        $ev = Start-Process $Setup -ArgumentList 'grant-channel' -Wait -PassThru -WindowStyle Hidden
        $afterGrant = ServiceReadSecurity
        Case 'G8-regrant-does-not-beat-policy' ($afterGrant -eq 'unreadable') "agentsetup grant-channel exit $($ev.ExitCode) with the policy in force: service identity read = $afterGrant (grant writes the configuration; the policy still wins)"
        # remove the GPO, refresh, restart: back to the configured ACE
        Remove-GPO -Name $GpoName
        [void](gpupdate /force /target:computer 2>&1)
        $noRestart = ServiceReadSecurity
        "INFO GPO removed and gpupdate run, no restart yet: service identity read = $noRestart; policy value present: $([bool](PolicyValue))"
        RestartEventLog
        Snap 'after-gpo-removed-and-eventlog-restart'
        $back = ServiceReadSecurity
        Case 'G9-removal-plus-restart-recovers' ($back -like 'readable*') "GPO removed + Event Log service restarted: service identity read = $back"
    } finally {
        Get-GPO -Name $GpoName -ErrorAction SilentlyContinue | Remove-GPO -ErrorAction SilentlyContinue
        [void](gpupdate /force /target:computer 2>&1)
        "INFO GPO left behind: $(@(Get-GPO -Name $GpoName -ErrorAction SilentlyContinue).Count); policy value present: $([bool](PolicyValue))"
    }
    Reset-Host
    Case 'Z-dc-healthy' ((Get-Service NTDS, Netlogon, KDC, DFSR, ADWS).Where({ $_.Status -ne 'Running' }).Count -eq 0) 'DC services running (NTDS Netlogon KDC DFSR ADWS)'
    "SUMMARY failures=$script:fail"
    exit $script:fail
}

try {
    # (a) a customer's log-access GPO that does not name the service SID: the MSI's ACE is shadowed.
    $gpo = New-GPO -Name $GpoName -Comment 'T-0557 lab; removed at the end of the run'
    [void](Set-GPRegistryValue -Name $GpoName -Key $PolKey -ValueName ChannelAccess -Type String -Value $stock)
    [void](New-GPLink -Name $GpoName -Target $dcOu -LinkEnabled Yes)
    $g = (gpupdate /force /target:computer 2>&1 | Out-String)
    "INFO gpupdate: $($g.Trim() -replace '\s+', ' ')"
    Snap 'after-gpo-without-service-ace'
    $t = WaitForRead 'unreadable' 60
    Case 'G4-live-gpo-has-no-immediate-effect' ($t -lt 0) "characterisation: a real GPO whose ChannelAccess lacks the service SID, gpupdate done: the service identity stayed readable for 60 s (became unreadable after: $t s; -1 = never) and wevtutil still reports the MSI ACE: $(HasAce). Mode gpo-restart shows when it does apply"
    Case 'G4-policy-value-written' ((PolicyValue) -eq $stock) 'gpupdate wrote the GPO value to the Policies key'

    # (b) the GPO is edited to name the service SID: the policy value follows the GPO.
    [void](Set-GPRegistryValue -Name $GpoName -Key $PolKey -ValueName ChannelAccess -Type String -Value $aceSddl)
    [void](gpupdate /force /target:computer 2>&1)
    Snap 'after-gpo-edited-to-name-service-sid'
    Case 'G5-policy-value-follows-edit' ((PolicyValue) -eq $aceSddl -and (ServiceReadSecurity) -like 'readable*') 'edited GPO value (includes the service SID) is in the Policies key and the service identity reads'

    # (c) the GPO is deleted: the Policies value is removed by the next gpupdate.
    Remove-GPO -Name $GpoName
    [void](gpupdate /force /target:computer 2>&1)
    Snap 'after-gpo-removed'
    Case 'G6-gpo-removed-value-cleared' (-not (PolicyValue) -and (HasAce) -and (ServiceReadSecurity) -like 'readable*') "GPO deleted + gpupdate: policy value absent=$(-not (PolicyValue)); MSI ACE in configuration=$(HasAce); service identity reads"
} finally {
    Get-GPO -Name $GpoName -ErrorAction SilentlyContinue | Remove-GPO -ErrorAction SilentlyContinue
    [void](gpupdate /force /target:computer 2>&1)
    "INFO GPO left behind: $(@(Get-GPO -Name $GpoName -ErrorAction SilentlyContinue).Count); policy value present: $([bool](PolicyValue))"
}
if (-not (HasAce)) { [void](Start-Process $Setup -ArgumentList 'grant-channel' -Wait -PassThru -WindowStyle Hidden) }

# ---------------------------------------------------------------------------------------------------------------
# Resource bounds, measured by Go lab tests that confine themselves exactly as the service does (Confine).
$tests = Join-Path $Build 'resource.test.exe'
if (Test-Path $tests) {
    foreach ($n in 'TestLabJobLimitsReadBack', 'TestLabCPUCapMeasured') {
        $o = & $tests "-test.run=^$n$" '-test.v' 2>&1 | Out-String -Width 300
        $o.TrimEnd()
        Case "R-$n" ($o -match "--- PASS: $n ") 'see LAB lines above'
    }

    # Load: a lab user, a Security log big enough not to wrap, a generator of network logons (4624 + 4634 + 4776 each).
    $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 28 | ForEach-Object { [char]$_ }) + 'aA1!'
    $user = 't0557gen'
    Get-ADUser -Filter "sAMAccountName -eq '$user'" -ErrorAction SilentlyContinue | Remove-ADUser -Confirm:$false -ErrorAction SilentlyContinue
    New-ADUser -Name $user -SamAccountName $user -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Description 'T-0557 lab load user; deleted at end of run'
    $dom = (Get-ADDomain).NetBIOSName
    wevtutil sl Security /ms:1073741824
    Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Diagnostics;using System.Runtime.InteropServices;using System.Threading;
public static class LogonGen{
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool LogonUser(string u,string d,string p,int type,int prov,out IntPtr tok);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 public static string Run(string user,string dom,string pw,int threads,int seconds){
  var lat=new List<double>(); long ok=0,fail=0; var end=DateTime.UtcNow.AddSeconds(seconds); var ts=new List<Thread>();
  for(int i=0;i<threads;i++){var t=new Thread(()=>{var mine=new List<double>();long o=0,f=0;
    while(DateTime.UtcNow<end){var sw=Stopwatch.StartNew();IntPtr tok;
      if(LogonUser(user,dom,pw,3,0,out tok)){CloseHandle(tok);o++;}else f++;
      sw.Stop();mine.Add(sw.Elapsed.TotalMilliseconds);}
    lock(lat){lat.AddRange(mine);ok+=o;fail+=f;}});t.Start();ts.Add(t);}
  foreach(var t in ts)t.Join();
  lat.Sort();double mean=0;foreach(var x in lat)mean+=x;mean/=Math.Max(1,lat.Count);
  double p95=lat.Count>0?lat[(int)(lat.Count*0.95)]:0, p99=lat.Count>0?lat[(int)(lat.Count*0.99)]:0;
  return String.Format("logons_ok={0} logons_failed={1} secs={2} logons_per_s={3:F0} lat_mean_ms={4:F2} lat_p95_ms={5:F2} lat_p99_ms={6:F2}",ok,fail,seconds,(double)ok/seconds,mean,p95,p99);}
}
'@
    function LastRecord { (Get-WinEvent -LogName Security -MaxEvents 1).RecordId }
    function CountCatalogue($fromRec, $toRec) {
        # Per event id, between two record ids; the sum over the ids the lab policy selects (4624 4634 4647 4648 4768 4769 4776).
        $x = "*[System[(EventRecordID>$fromRec and EventRecordID<=$toRec)]]"
        $g = @(Get-WinEvent -LogName Security -FilterXPath $x -ErrorAction SilentlyContinue | Group-Object Id)
        $sel = 4624, 4634, 4647, 4648, 4768, 4769, 4776
        $sum = 0; foreach ($e in $g) { if ($sel -contains [int]$e.Name) { $sum += $e.Count } }
        "$sum (by id: $((($g | Sort-Object Count -Descending | Select-Object -First 8) | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '))"
    }
    # The agent's data directory check (CheckDataDir) accepts only SYSTEM, Administrators and the process's own identity.
    # The tests run as Administrator, so they get a data directory that grants exactly those two.
    $LabRoot = Join-Path $env:ProgramData 'skenzeriq-t0557'
    $LabData = Join-Path $LabRoot 'data'
    Remove-Item -Recurse -Force $LabRoot -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $LabRoot | Out-Null
    icacls $LabRoot /inheritance:r /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)F' /grant 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
    New-Item -ItemType Directory -Force $LabData | Out-Null
    try {
        foreach ($th in $Threads) {
            # baseline: the generator alone, no agent process.
            $r0 = LastRecord
            $base = [LogonGen]::Run($user, $dom, $pw, $th, 20)
            $r1 = LastRecord
            "INFO load threads=$th BASELINE (no agent): $base; security events written $($r1 - $r0)"

            # with the confined agent collecting
            $log = "$Out\load-$th.txt"
            Remove-Item $log -ErrorAction SilentlyContinue
            $p = Start-Process $tests -ArgumentList "-test.run=^TestLabResourceLoad$", '-test.v', "-labsecs=$LoadSeconds", '-labrate=3000', "-labdata=$LabData" -RedirectStandardOutput $log -RedirectStandardError "$Out\load-$th.err" -PassThru -WindowStyle Hidden
            for ($i = 0; $i -lt 60 -and -not ((Test-Path $log) -and (Select-String -Path $log -Pattern '^LAB ready' -Quiet)); $i++) { Start-Sleep 1 }
            $s0 = LastRecord
            $with = [LogonGen]::Run($user, $dom, $pw, $th, $LoadSeconds)
            $s1 = LastRecord
            [void]$p.WaitForExit(120000)
            $cat = CountCatalogue $s0 $s1
            "INFO load threads=$th WITH AGENT: $with; security events written $($s1 - $s0); catalogue-id events in the log for the window $cat"
            Get-Content $log | Where-Object { $_ -match '^LAB |^--- |^FAIL|^PASS' }
            $ok = (Select-String -Path $log -Pattern '--- PASS: TestLabResourceLoad' -Quiet)
            Case "R-load-$th" $ok "TestLabResourceLoad with $th generator threads (numbers above)"
        }
        # Capacity: read the whole backlog the generator left (and the DC's own events) through the confined host.
        $oldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1).RecordId
        $newest = LastRecord
        "INFO catch-up window: Security record ids $oldest .. $newest"
        $log = "$Out\catchup.txt"
        Remove-Item $log -ErrorAction SilentlyContinue
        $o = & $tests '-test.run=^TestLabResourceCatchUp$' '-test.v' "-labafter=$oldest" "-labdata=$LabData" 2>&1 | Out-String -Width 300
        $o.TrimEnd()
        Case 'R-catchup' ($o -match '--- PASS: TestLabResourceCatchUp') 'TestLabResourceCatchUp (LAB catchup line above)'
    } finally {
        Get-ADUser -Filter "sAMAccountName -eq '$user'" -ErrorAction SilentlyContinue | Remove-ADUser -Confirm:$false -ErrorAction SilentlyContinue
        wevtutil sl Security /ms:$origMax
        Remove-Item -Recurse -Force $LabRoot -ErrorAction SilentlyContinue
        "INFO lab user removed: $(-not (Get-ADUser -Filter "sAMAccountName -eq '$user'" -ErrorAction SilentlyContinue)); Security maxSize restored to $((wevtutil gl Security | Select-String 'maxSize:').Line.Trim())"
    }
} else { Case 'R-missing' $false 'resource.test.exe not uploaded' }

# ---------------------------------------------------------------------------------------------------------------
Reset-Host
Case 'Z-restored' ((ChannelSddl) -eq $stock -and -not (PolicyValue) -and -not (Test-Path "$DataRoot\agent")) 'channelAccess back to baseline, no policy value, no agent data'
Case 'Z-dc-healthy' ((Get-Service NTDS, Netlogon, KDC).Where({ $_.Status -ne 'Running' }).Count -eq 0) 'DC services running'
"SUMMARY failures=$script:fail"
exit $script:fail
