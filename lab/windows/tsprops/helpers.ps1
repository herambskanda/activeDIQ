# Helpers for the userParameters capture on the lab DC (T-1890). Dot-sourced by lab/windows/bin/capture-tsprops.
# Lab only. No credentials in here; runs as the WinRM Administrator already on the DC.
$ErrorActionPreference = 'Stop'
$base = 'DC=win,DC=activediq,DC=test'
$ou   = "OU=tspfix,$base"
Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Wts {
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool WTSQueryUserConfigW(string server, string user, int cls, out IntPtr buf, out int bytes);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
  public static string Q(string server, string user, int cls, bool str) {
    IntPtr p; int n;
    if (!WTSQueryUserConfigW(server, user, cls, out p, out n)) return "ERR" + Marshal.GetLastWin32Error();
    try { return str ? Marshal.PtrToStringUni(p) : Marshal.ReadInt32(p).ToString(); } finally { WTSFreeMemory(p); }
  }
}
'@
$script:ldap = $null
function Get-Ldap { if (-not $script:ldap) { $c = New-Object System.DirectoryServices.Protocols.LdapConnection("localhost:389"); $c.AuthType='Negotiate'; $c.Bind(); $script:ldap = $c }; $script:ldap }
function New-TspUser($sam) {
  if (Get-ADUser -Filter "samAccountName -eq '$sam'") { Remove-ADUser $sam -Confirm:$false }
  if (-not [adsi]::Exists("LDAP://$ou")) { New-ADOrganizationalUnit -Name tspfix -Path $base -ProtectedFromAccidentalDeletion $false }
  New-ADUser -Name $sam -SamAccountName $sam -Path $ou -Enabled $false
  (Get-ADUser $sam).DistinguishedName
}
function Set-Ts($dn, $prop, $val) { $u = [adsi]"LDAP://$dn"; $u.psbase.InvokeSet($prop, $val); $u.SetInfo() }
# Raw LDAP octets of userParameters (what a connector receives), hex; '' when absent.
function Get-RawOctets($dn, $server) {
  $c = Get-Ldap
  $req = New-Object System.DirectoryServices.Protocols.SearchRequest($dn, '(objectClass=*)', 'Base', 'userParameters')
  $r = $c.SendRequest($req)
  if ($r.Entries.Count -eq 0 -or -not $r.Entries[0].Attributes.Contains('userParameters')) { return '(absent)' }
  $b = $r.Entries[0].Attributes['userParameters'].GetValues([byte[]])[0]
  ($b | % { '{0:x2}' -f $_ }) -join ''
}
function Set-RawOctets($dn, [byte[]]$octets) {
  $c = Get-Ldap
  $m = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
  $m.Name = 'userParameters'; $m.Operation = 'Replace'; [void]$m.Add($octets)
  $req = New-Object System.DirectoryServices.Protocols.ModifyRequest($dn, $m)
  [void]$c.SendRequest($req)
}
$WtsInt = [ordered]@{ InheritInitialProgram=2; AllowLogon=3; MaxConnection=4; MaxDisconnection=5; MaxIdle=6; ClientDrives=7; ClientPrinters=8; DefaultPrinter=9; BrokenTimeout=10; Reconnect=11; Shadowing=14; RemoteHomeDir=18 }
$WtsStr = [ordered]@{ InitialProgram=0; WorkDirectory=1; ProfilePath=15; HomeDir=16; HomeDirDrive=17 }
function Get-WtsReadback($sam) {
  $o = [ordered]@{}
  foreach ($k in $WtsInt.Keys) { $o[$k] = [Wts]::Q($env:COMPUTERNAME, $sam, $WtsInt[$k], $false) }
  foreach ($k in $WtsStr.Keys) { $o[$k] = [Wts]::Q($env:COMPUTERNAME, $sam, $WtsStr[$k], $true) }
  $o
}
$AdsiProps = 'AllowLogon','EnableRemoteControl','MaxConnectionTime','MaxDisconnectionTime','MaxIdleTime','ReconnectionAction','BrokenConnectionAction','TerminalServicesHomeDirectory','TerminalServicesHomeDrive','TerminalServicesProfilePath','TerminalServicesInitialProgram','TerminalServicesWorkDirectory'
# What ADUC itself would show: the same IADsTSUserEx properties it binds to. $null = the property is not present / not readable.
function Get-AdsiReadback($dn) {
  $o = [ordered]@{}
  foreach ($k in $AdsiProps) { $u = [adsi]"LDAP://$dn"; try { $v = $u.psbase.InvokeGet($k); $o[$k] = if ($v -is [string]) { $v } else { [int64]$v } } catch { $o[$k] = $null } }
  $o
}
function Emit($label, $sam, $dn) {
  $rec = [ordered]@{ label=$label; sam=$sam; octets=(Get-RawOctets $dn); wts=(Get-WtsReadback $sam); adsi=(Get-AdsiReadback $dn) }
  "REC|" + ($rec | ConvertTo-Json -Compress -Depth 4)
}
