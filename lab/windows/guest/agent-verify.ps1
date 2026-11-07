# Lab cases for the DC agent MSI (T-0648, ADR-0006). Runs ON the lab DC as an elevated Administrator,
# normally through lab/windows/bin/agent-verify. Prints "CASE <id> PASS|FAIL <detail>" lines and exits
# non-zero if any case failed. It installs, repairs, upgrades and uninstalls the agent: run it on the
# lab DC only, never on a real domain controller. Runbook: knowledge/development/runbooks/windows-lab.md §13.
#
# Inputs (C:\lab\build): activediq-agent-<ver>.msi (built from packaging/windows/agent/Agent.wxs),
# agentsetup.exe, and the Go test binaries agent.test.exe. No credential is committed or logged: the
# lab user's password is generated per run and never printed.
param([string]$Build = 'C:\lab\build', [string]$Version = '0.0.1')
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Msi = Join-Path $Build "activediq-agent-$Version.msi"
$Setup = 'C:\Program Files\skenzeriq\agent\agentsetup.exe'
$Svc = 'activeDIQAgent'
$SvcAcct = 'NT SERVICE\activeDIQAgent'
$DataRoot = Join-Path $env:ProgramData 'skenzeriq'
$Out = 'C:\lab\out'
$script:fail = 0

function Case($id, [bool]$ok, $detail) {
    if (-not $ok) { $script:fail++ }
    "CASE $id $(if ($ok) { 'PASS' } else { 'FAIL' }) $detail"
}
function MsiRun($args_, $log) {
    $p = Start-Process msiexec -ArgumentList "$args_ /qn /l*v `"$Build\$log`"" -Wait -PassThru
    $p.ExitCode
}
function ChannelSddl { (wevtutil gl Security | Select-String 'channelAccess:').Line -replace '^\s*channelAccess:\s*', '' }
function SvcSidString { try { (New-Object Security.Principal.NTAccount($SvcAcct)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null } }
function HasAce { $sid = SvcSidString; [bool]($sid -and ((ChannelSddl) -like "*;;;$sid)*")) }
function Uninstall {
    # By product code from Add/Remove Programs: a rebuilt MSI has a new ProductCode, so /x <file> would miss it.
    foreach ($k in Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'activeDIQ Agent') {
        [void](MsiRun "/x $($k.PSChildName)" 'uninstall.log')
    }
}
function Reset-Host {
    Uninstall
    if (Get-Service $Svc -ErrorAction SilentlyContinue) { sc.exe delete $Svc | Out-Null }
    Remove-DataRoot
}
function Remove-DataRoot {
    # A junction must be removed as a link, never recursed into.
    if (Test-Path $DataRoot) {
        if ((Get-Item $DataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { (Get-Item $DataRoot -Force).Delete() }
        else { Remove-Item -Recurse -Force $DataRoot }
    }
}
# Run a program as the agent's own identity. Task Scheduler cannot take NT SERVICE\<name> as a principal
# (0x80070534, by name or by SID) and a service started this way has no usable console, so the program is
# run as the service itself: the service image is pointed at it for a moment and SCM starts it with the real
# restricted service token. The program must write $doneFile (or, with no $doneFile, just be given $waitSec).
# Returns the content of $doneFile, or $null if it never appeared.
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
    } finally {
        Stop-Service $Svc -ErrorAction SilentlyContinue
        Set-ItemProperty $k ImagePath $orig
    }
    if ($doneFile) { if (Test-Path $doneFile) { (Get-Content $doneFile -Raw).Trim() } else { $null } }
}
# Read the Security channel as the service identity, through the agent's own event source (Go lab test).
function ServiceReadSecurity {
    RunAsService "`"$Build\agent.test.exe`" -test.run=TestLabReadAsService -labout=$Out\svc-read.txt" "$Out\svc-read.txt"
}
function AppEvents($id, $since) {
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = $id; StartTime = $since } -ErrorAction SilentlyContinue)
}
function TokenOfServiceProcess {
    # SCM builds the service token from the service configuration, not from the binary. Point the image
    # at a long-running stub for a few seconds, read that process's token from outside, then restore.
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Text;
public static class AgentTok{
 [DllImport("kernel32.dll")]static extern IntPtr OpenProcess(uint a,bool i,int p);
 [DllImport("advapi32.dll")]static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
 [DllImport("advapi32.dll")]static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,int l,out int r);
 [DllImport("advapi32.dll")]static extern bool LookupPrivilegeName(string s,ref long luid,StringBuilder n,ref int l);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern bool ConvertSidToStringSid(IntPtr s,out string o);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 public static string Dump(int pid){
  IntPtr p=OpenProcess(0x1000,false,pid); if(p==IntPtr.Zero)return "noproc";
  IntPtr t; if(!OpenProcessToken(p,8,out t)){CloseHandle(p);return "notoken";}
  var o=new StringBuilder(); int r; IntPtr b=Marshal.AllocHGlobal(8192);
  GetTokenInformation(t,1,b,8192,out r); string sid; ConvertSidToStringSid(Marshal.ReadIntPtr(b),out sid); o.Append("user="+sid);
  if(GetTokenInformation(t,3,b,8192,out r)){int n=Marshal.ReadInt32(b);for(int i=0;i<n;i++){long luid=Marshal.ReadInt64(b,4+i*12);var nm=new StringBuilder(64);int l=64;LookupPrivilegeName(null,ref luid,nm,ref l);o.Append(" priv="+nm);}}
  if(GetTokenInformation(t,11,b,8192,out r)){o.Append(" restrictingSids="+Marshal.ReadInt32(b));}
  CloseHandle(t);CloseHandle(p);return o.ToString();}
}
'@ -ErrorAction SilentlyContinue
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc"
    $orig = (Get-ItemProperty $k).ImagePath
    Stop-Service $Svc -ErrorAction SilentlyContinue
    Set-ItemProperty $k ImagePath 'C:\Windows\System32\ping.exe -n 25 127.0.0.1'
    try {
        Start-Process sc.exe -ArgumentList "start $Svc" -WindowStyle Hidden
        Start-Sleep 3
        $p = Get-Process ping -ErrorAction SilentlyContinue | Select-Object -First 1
        $d = if ($p) { [AgentTok]::Dump($p.Id) } else { 'no-process' }
        if ($p) { Stop-Process $p.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep 2
        $d
    } finally {
        Stop-Service $Svc -ErrorAction SilentlyContinue
        Set-ItemProperty $k ImagePath $orig
    }
}

New-Item -ItemType Directory -Force $Out | Out-Null
Reset-Host
# Stock WS2025 Security channel ACL; a leftover service-SID ACE (an interrupted earlier run) is scrubbed to it.
$stock = 'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)'
if ((ChannelSddl) -like '*S-1-5-80-*') { "INFO scrubbing a stale service ACE left by an interrupted run"; wevtutil sl Security /ca:$stock }
$cleanSddl = ChannelSddl
$baseline = $cleanSddl
"INFO baseline Security channelAccess: $baseline"
Case 'T0' ($cleanSddl -notlike '*S-1-5-80-*') 'no service-SID ACE before install'

# ---- install, identity, token (acceptance 1)
$rc = MsiRun "/i `"$Msi`"" 'install.log'
Case 'A1-install' ($rc -eq 0) "msiexec exit $rc"
$svcObj = Get-Service $Svc -ErrorAction SilentlyContinue
Case 'A1-service' ($null -ne $svcObj) 'service registered'
Case 'A1-sidtype' ([bool]((sc.exe qsidtype $Svc | Out-String) -match 'RESTRICTED'))  'service SID type RESTRICTED'
$q = (sc.exe qprivs $Svc | Out-String)
Case 'A2-qprivs' (($q -match 'SeChangeNotifyPrivilege') -and ($q -notmatch 'SeImpersonate|SeAssignPrimary|SeDebug|SeTcb|SeBackup|SeRestore')) ($q -replace '\s+', ' ')
$tok = TokenOfServiceProcess
Case 'A2-token' (($tok -match 'priv=SeChangeNotifyPrivilege') -and (($tok -split 'priv=').Count -eq 2) -and ($tok -match 'restrictingSids=[1-9]') -and ($tok -match "user=$([regex]::Escape((SvcSidString)))")) $tok
Case 'A2-startname' ((sc.exe qc $Svc | Out-String) -match [regex]::Escape($SvcAcct)) 'runs as the virtual account, not LocalSystem or a domain account'
Case 'A3-ace' (HasAce) 'Security channel carries the service-SID ACE'
$kept = $baseline -replace '^O:[A-Z]+G:[A-Z]+D:', ''
$still = ((ChannelSddl) -like "*(A;;0x5;;;BA)*" -or (ChannelSddl) -like '*;;;BA)*') -and ((ChannelSddl) -like '*;;;SY)*')
Case 'A3-others-kept' $still 'SYSTEM and Administrators ACEs untouched by grant'
$res = ServiceReadSecurity
Case 'A3-readable' ($res -like 'readable events=*') "Security read as $SvcAcct through the agent's event source: $res"
$dacl = (icacls "$DataRoot\agent" | Out-String)
Case 'A5-datadir' (($dacl -match 'activeDIQAgent') -and ($dacl -match 'SYSTEM') -and ($dacl -match 'Administrators') -and ($dacl -notmatch 'Users|Everyone|Authenticated')) ($dacl -replace '\s+', ' ')
Case 'A5-eventsource' ([Diagnostics.EventLog]::SourceExists('activeDIQ Agent')) 'Application event source registered'
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'activeDIQ Agent' } -MaxEvents 1 -ErrorAction SilentlyContinue
$msg = if ($ev) { $ev.Message } else { '' }
# Known gap, ticketed (T-0813): the event source's message file is EventCreate.exe, which only defines ids 1-1000,
# so the agent's ids (101, 102, 4101) render with an empty description. Reported, not failed, until fixed.
if ($msg) { Case 'A5-event-renders' $true "event text rendered: '$msg'" } else { "KNOWN A5-event-renders T-0813: event text does not render (message file is EventCreate.exe)" }

# ---- GPO reset of the channel ACL (simulated with the same call a GPO makes), then re-grant
wevtutil sl Security /ca:$cleanSddl
Case 'G1-reset' (-not (HasAce)) 'channel ACL reset to baseline removes the ACE'
$res = ServiceReadSecurity
Case 'G1-unreadable' ($res -eq 'unreadable') "after the reset the service identity gets ErrUnreadable: $res"
$p = Start-Process $Setup -ArgumentList 'grant-channel' -Wait -PassThru -WindowStyle Hidden
Case 'G2-regrant' ($p.ExitCode -eq 0 -and (HasAce)) "grant-channel exit $($p.ExitCode)"
$n1 = ([regex]::Matches((ChannelSddl), 'S-1-5-80-')).Count
$p = Start-Process $Setup -ArgumentList 'grant-channel' -Wait -PassThru -WindowStyle Hidden
$n2 = ([regex]::Matches((ChannelSddl), 'S-1-5-80-')).Count
Case 'G3-idempotent' ($p.ExitCode -eq 0 -and $n1 -eq $n2 -and $n1 -ge 1) "grant twice -> $n2 service ACE(s)"

# ---- agent starts and stops cleanly when not enrolled (token + confine pass, then refusal)
$t0 = Get-Date
Start-Service $Svc -ErrorAction SilentlyContinue
Start-Sleep 4
$e101 = AppEvents 101 $t0
Case 'S1-not-enrolled' ($e101.Count -ge 1 -and ($e101[0].Properties[0].Value -match 'not enrolled')) "event 101: $(if ($e101) { $e101[0].Properties[0].Value })"
Stop-Service $Svc -ErrorAction SilentlyContinue

# ---- corrupt agent.json: refuses to start, DC unaffected
$cfg = 'C:\Program Files\skenzeriq\agent\agent.json'
$good = Get-Content $cfg -Raw
Set-Content $cfg '{ this is not json' -Encoding ascii
$t0 = Get-Date
Start-Service $Svc -ErrorAction SilentlyContinue
Start-Sleep 4
$e101 = AppEvents 101 $t0
Case 'F1-corrupt-config' ($e101.Count -ge 1) "event 101 on corrupt agent.json: $(if ($e101) { $e101[0].Properties[0].Value })"
Stop-Service $Svc -ErrorAction SilentlyContinue
Set-Content $cfg $good -Encoding ascii -NoNewline
Case 'F1-dc-healthy' ((Get-Service NTDS, Netlogon, KDC).Where({ $_.Status -ne 'Running' }).Count -eq 0) 'NTDS, Netlogon and KDC running'
$null = nltest /dsgetdc:win.activediq.test 2>&1
Case 'F1-dc-auth' ($LASTEXITCODE -eq 0) 'DC locator answers (nltest /dsgetdc)'

# ---- repair, then failed major upgrade over an installed agent (T-0732 residual)
$rc = MsiRun "/fa `"$Msi`"" 'repair.log'
Case 'U1-repair' ($rc -eq 0 -and (HasAce)) "repair exit $rc, ACE present=$(HasAce)"
$wxs = Get-Content (Join-Path $Build 'Agent.wxs') -Raw
$bad = $wxs -replace '(<InstallExecuteSequence>)', '<CustomAction Id="LabFail" Directory="AgentDir" Execute="deferred" Impersonate="no" Return="check" ExeCommand="&quot;[SystemFolder]cmd.exe&quot; /c exit 1" />$1'
$bad = $bad -replace '(<Custom Action="GrantChannel"[^>]*/>)', '$1<Custom Action="LabFail" After="GrantChannel" Condition="NOT REMOVE" />'
Set-Content (Join-Path $Build 'Agent-fail.wxs') $bad -Encoding utf8
$env:DOTNET_ROOT = 'C:\lab\tools\dotnet'; $env:PATH = "C:\lab\tools\dotnet;$env:PATH"
$v2 = '0.0.2'
& C:\lab\tools\wix\wix.exe build (Join-Path $Build 'Agent-fail.wxs') -ext WixToolset.Util.wixext -d Version=$v2 -d AgentExe=$Build\activediq-agent.exe -d SetupExe=$Build\agentsetup.exe -arch x64 -wx -sw1149 -o (Join-Path $Build "activediq-agent-fail-$v2.msi") 2>&1 | Out-Null
$rc = MsiRun "/i `"$Build\activediq-agent-fail-$v2.msi`"" 'upgrade-fail.log'
Case 'U2-upgrade-fails' ($rc -eq 1603) "forced failure exit $rc"
$aceAfter = HasAce
$verAfter = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'activeDIQ Agent').DisplayVersion
Case 'U2-old-version-kept' ($verAfter -eq $Version) "installed version after rollback: $verAfter"
# Documented residual (dc-agent-operations.md): rollback removes the ACE that existed before.
"INFO U2 residual: Security ACE present after failed upgrade = $aceAfter (expected False per T-0732)"
Case 'U2-residual-reproduced' (-not $aceAfter) 'RollbackGrantChannel removed the pre-existing ACE; the installed agent would report CHANNEL_UNREADABLE'
$t0 = Get-Date
$p = Start-Process $Setup -ArgumentList 'grant-channel' -Wait -PassThru -WindowStyle Hidden
Case 'U2-recovery' ($p.ExitCode -eq 0 -and (HasAce)) 'grant-channel restores read access'
$e = AppEvents 102 $t0
"INFO event 102 (channel unreadable) count since upgrade failure: $($e.Count)"

# ---- agentsetup refusals: planted junction, user-owned parent (T-0555 review cases 1 and 2)
Stop-Service $Svc -ErrorAction SilentlyContinue
Uninstall
Remove-DataRoot
$pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ }) + 'aA1!'
$u = 'agentverifyusr'
net user $u /delete 2>&1 | Out-Null
net user $u $pw /add /y | Out-Null
$tmpSetup = Join-Path $Build 'agentsetup.exe'

$target = 'C:\lab\junction-target'
New-Item -ItemType Directory -Force $target | Out-Null
cmd /c mklink /J "$DataRoot" "$target" | Out-Null
$p = Start-Process $tmpSetup -ArgumentList 'prepare-datadir' -Wait -PassThru -WindowStyle Hidden
Case 'D1-junction-refused' ($p.ExitCode -ne 0 -and -not (Test-Path "$target\agent")) "prepare-datadir exit $($p.ExitCode); junction target untouched"
Remove-DataRoot

New-Item -ItemType Directory $DataRoot | Out-Null
icacls $DataRoot /setowner $u | Out-Null
$own = (Get-Acl $DataRoot).Owner
$p = Start-Process $tmpSetup -ArgumentList 'prepare-datadir' -Wait -PassThru -WindowStyle Hidden
Case 'D2-user-owned-parent-refused' ($own -like "*$u" -and $p.ExitCode -ne 0 -and -not (Test-Path "$DataRoot\agent")) "owner $own; prepare-datadir exit $($p.ExitCode)"
Remove-DataRoot

net user $u /delete | Out-Null

# ---- Go lab tests for the Windows adapters (built with -tags windowslab, uploaded by agent-verify)
$gt = Join-Path $Build 'agent.test.exe'
if (Test-Path $gt) {
    $o = & $gt '-test.run=TestLab' '-test.v' 2>&1 | Out-String -Width 300
    $o.TrimEnd()
    foreach ($n in 'TestLabCheckDataDir', 'TestLabOldestRecord') {
        Case "GO-$n" ($o -match "--- PASS: $n ") "see go test output above"
    }
} else { Case 'GO-missing' $false 'agent.test.exe not uploaded' }

# ---- uninstall cleanliness
$rc = MsiRun "/i `"$Msi`"" 'install2.log'
Case 'X0-reinstall' ($rc -eq 0 -and (HasAce)) "msiexec exit $rc"
# revoke-channel failing writes Application event 4101 (review case 6): run it as the service identity, which is
# not an administrator and so cannot change the channel configuration.
$t0 = Get-Date
[void](RunAsService "`"$Setup`" revoke-channel" $null 8)
$e4101 = AppEvents 4101 $t0
Case 'E6-revoke-failure-event' ($e4101.Count -ge 1) "revoke-channel as the service identity (not an administrator): Application event 4101 count $($e4101.Count)"
$rc = MsiRun "/x `"$Msi`"" 'uninstall.log'
Case 'X1-uninstall' ($rc -eq 0) "msiexec exit $rc"
Case 'X1-service-gone' (-not (Get-Service $Svc -ErrorAction SilentlyContinue)) 'no service left'
Case 'X1-ace-gone' (-not (HasAce) -and ((ChannelSddl) -eq $cleanSddl -or (ChannelSddl) -eq $baseline)) 'Security channelAccess back to baseline'
Case 'X1-files-gone' (-not (Test-Path 'C:\Program Files\skenzeriq\agent')) 'Program Files tree removed'
Case 'X1-datadir-kept' (Test-Path "$DataRoot\agent") 'data directory kept by design (outbox, policy anchor)'
Case 'X1-eventsource-gone' (-not [Diagnostics.EventLog]::SourceExists('activeDIQ Agent')) 'event source removed'
Case 'X1-no-product' (-not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'activeDIQ Agent')) 'no Add/Remove Programs entry'
Case 'X1-no-listener' ((Get-NetFirewallRule -DisplayName '*activeDIQ*' -ErrorAction SilentlyContinue).Count -eq 0) 'no firewall rule created'
Case 'X1-dc-healthy' ((Get-Service NTDS, Netlogon, KDC).Where({ $_.Status -ne 'Running' }).Count -eq 0) 'DC services running after uninstall'
Remove-DataRoot

"SUMMARY failures=$script:fail"
exit $script:fail
