# T-1510 (TM-D31 rules 3 and 7): where do the msDS-Repl* attributes live, which right do they need, and does DirSync under
# LDAP_DIRSYNC_OBJECT_SECURITY deliver deletes for a non-replicating account? Runs ON dc1 (lab only, A-0025) over WinRM,
# under with-dc1-lock, driven by lab/windows/bin/repl-rights-lab. The driver passes the service account's password in $env:T1510_SVC.
#
# Writes (all reverted in `finally`, verified by hashing each partition head's DACL before and after):
#   OU=T1510-Lab with two throwaway users (random passwords, never printed), two throwaway objects for the DirSync test, and
#   one ACE on partition heads: DS-Replication-Monitor-Topology (rightsGuid read from the forest, not hard-coded) for t1510-mon.
# It never grants Get-Changes, never touches Administrators/Domain Admins, never writes to Configuration beyond that one ACE.
# Output is one `TAG|field|...` line per fact, ending in DONE; the driver parses it (lib/replrights.py).
$ErrorActionPreference = 'Stop'
$SvcPassword = $env:T1510_SVC
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices.Protocols
$P = [DirectoryServices.Protocols.SearchScope]::Base
function Out-Fact { param([string[]]$f) ($f | ForEach-Object { ("$_" -replace '[\r\n|]+', ' ') }) -join '|' }
function Say { param([string[]]$f) Write-Output (Out-Fact $f) }

$rd = Get-ADRootDSE
$head = $rd.defaultNamingContext; $cfg = $rd.configurationNamingContext; $sch = $rd.schemaNamingContext
$dom = Get-ADDomain
$dcName = $env:COMPUTERNAME + '.' + $dom.DNSRoot
$ntds = (Get-ADDomainController -Identity $env:COMPUTERNAME).NTDSSettingsObjectDN
$ou = "OU=T1510-Lab,$head"
$bases = [ordered]@{ rootDSE = ''; domainHead = $head; configHead = $cfg; schemaHead = $sch; ntdsSettings = $ntds }
$attrs = @('msDS-ReplAllInboundNeighbors', 'msDS-ReplPendingOps', 'msDS-ReplConnectionFailures', 'msDS-ReplLinkFailures')
$rbEnabled = [bool]@((Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' }).EnabledScopes).Count
Say 'SETUP', 'domain', $dom.DNSRoot
Say 'SETUP', 'dc', $dcName
Say 'SETUP', 'dcs_in_domain', (@(Get-ADDomainController -Filter * -Server localhost).Count)
Say 'SETUP', 'forest_domains', ((Get-ADForest).Domains -join ',')
Say 'SETUP', 'recycle_bin', $rbEnabled
Say 'SETUP', 'inbound_partners_per_repadmin', (@(repadmin /showrepl localhost /csv 2>$null | Select-Object -Skip 1).Count)

function New-RandomPassword { $b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'Aa1!' + [Convert]::ToBase64String($b) }
function Get-AclHash($dn) {
    $a = Get-Acl "AD:$dn"
    $rows = $a.Access | ForEach-Object { "$($_.IdentityReference)|$($_.ActiveDirectoryRights)|$($_.AccessControlType)|$($_.ObjectType)|$($_.InheritanceType)|$($_.InheritedObjectType)|$($_.IsInherited)" } | Sort-Object
    $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(($rows -join "`n")))
    ([BitConverter]::ToString($h) -replace '-', '').Substring(0, 16)
}
function Connect-Ldap($user, $pass) {
    $c = New-Object DirectoryServices.Protocols.LdapConnection((New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($dcName, 389)))
    $c.SessionOptions.ProtocolVersion = 3; $c.AuthType = 'Negotiate'
    $c.SessionOptions.Signing = $true; $c.SessionOptions.Sealing = $true
    if ($user) { $c.Credential = New-Object Net.NetworkCredential($user, $pass) }
    $c.Bind()
    $c
}
function Get-Err($e) {
    $x = $e.Exception
    if ($x -is [DirectoryServices.Protocols.DirectoryOperationException]) { return "DirectoryOperationException:$($x.Response.ResultCode)" }
    if ($x -is [DirectoryServices.Protocols.LdapException]) { return "LdapException:$($x.ErrorCode)" }
    "$($x.GetType().Name)"
}
# One base search for the four attributes plus a sentinel that always exists, so "entry returned, attributes absent" is
# distinguishable from "no entry / error".
function Read-Repl($label, $state, $c) {
    foreach ($bn in $bases.Keys) {
        $q = New-Object DirectoryServices.Protocols.SearchRequest($bases[$bn], '(objectClass=*)', $P)
        [void]$q.Attributes.Add($(if ($bn -eq 'rootDSE') { 'currentTime' } else { 'distinguishedName' }))
        foreach ($a in $attrs) { [void]$q.Attributes.Add($a) }
        try {
            $r = $c.SendRequest($q)
            if ($r.Entries.Count -ne 1) { Say 'READ', $label, $state, $bn, 'entries', $r.Entries.Count; continue }
            $e = $r.Entries[0]
            $got = @($attrs | Where-Object { $e.Attributes.Contains($_) })
            $len = ($got | ForEach-Object { "$_=$(@($e.Attributes[$_].GetValues([string])).Count)v/$(($e.Attributes[$_].GetValues([string]) | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum)c" }) -join ';'
            Say 'READ', $label, $state, $bn, 'entry', "sentinel=$($e.Attributes.Count -ge 1)", "repl_attrs_returned=$($got.Count)", $len
        } catch { Say 'READ', $label, $state, $bn, 'error', (Get-Err $_) }
    }
}
function Grant-Monitor($sid, $dn, $guid) {
    $acl = Get-Acl "AD:$dn"
    $acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $guid, 'None')))
    Set-Acl "AD:$dn" $acl
}
function Revoke-All($sid, $dn) {
    $acl = Get-Acl "AD:$dn"; $acl.PurgeAccessRules($sid); Set-Acl "AD:$dn" $acl
}

# DirSync with LDAP_DIRSYNC_OBJECT_SECURITY | INCREMENTAL_VALUES from the domain head. Returns the entries seen and the cookie.
function Invoke-DirSync($c, [byte[]]$cookie) {
    $seen = @(); $err = $null
    $ctl = New-Object DirectoryServices.Protocols.DirSyncRequestControl
    $ctl.Option = [DirectoryServices.Protocols.DirectorySynchronizationOptions]::ObjectSecurity -bor [DirectoryServices.Protocols.DirectorySynchronizationOptions]::IncrementalValues
    $ctl.AttributeCount = 1048576
    if ($cookie) { $ctl.Cookie = $cookie }
    do {
        $q = New-Object DirectoryServices.Protocols.SearchRequest($head, '(objectClass=*)', [DirectoryServices.Protocols.SearchScope]::Subtree)
        foreach ($a in 'objectGUID', 'isDeleted', 'whenChanged', 'description', 'msDS-ReplAttributeMetaData') { [void]$q.Attributes.Add($a) }
        [void]$q.Controls.Add($ctl)
        try { $r = $c.SendRequest($q) } catch { return @{ error = (Get-Err $_); entries = $seen; cookie = $cookie } }
        $seen += @($r.Entries)
        $rc = $r.Controls | Where-Object { $_ -is [DirectoryServices.Protocols.DirSyncResponseControl] }
        $ctl.Cookie = $rc.Cookie; $more = $rc.MoreData
        $q.Controls.Clear()
    } while ($more)
    @{ error = $null; entries = $seen; cookie = $ctl.Cookie }
}
function Guid-Of($e) { if ($e.Attributes.Contains('objectGUID')) { ([guid]($e.Attributes['objectGUID'].GetValues([byte[]])[0])).ToString() } else { '' } }

$rights = [guid](Get-ADObject "CN=DS-Replication-Monitor-Topology,CN=Extended-Rights,$cfg" -Properties rightsGuid).rightsGuid
Say 'SETUP', 'monitor_topology_rightsGuid_from_forest', $rights
$before = @{}; foreach ($d in $head, $cfg, $sch) { $before[$d] = Get-AclHash $d }
$passMon = New-RandomPassword; $passNone = New-RandomPassword
$mon = $null; $none = $null; $created = $false
try {
    if (Get-ADOrganizationalUnit -Filter { Name -eq 'T1510-Lab' } -SearchBase $head -SearchScope OneLevel) {
        Get-ADOrganizationalUnit $ou | Set-ADObject -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit $ou -Recursive -Confirm:$false
    }
    New-ADOrganizationalUnit -Name 'T1510-Lab' -Path $head -ProtectedFromAccidentalDeletion $false
    $created = $true
    foreach ($n in 't1510-mon', 't1510-none') {
        New-ADUser -Name $n -SamAccountName $n -UserPrincipalName "$n@$($dom.DNSRoot)" -Path $ou -Enabled $true -AccountPassword (ConvertTo-SecureString $(if ($n -eq 't1510-mon') { $passMon } else { $passNone }) -AsPlainText -Force)
    }
    $mon = Get-ADUser t1510-mon; $none = Get-ADUser t1510-none
    # Neither principal is in any privileged group (the default Authenticated Users read is all they have).
    Say 'SETUP', 'mon_memberOf', (@(Get-ADPrincipalGroupMembership $mon | ForEach-Object Name) -join ',')
    Say 'SETUP', 'none_memberOf', (@(Get-ADPrincipalGroupMembership $none | ForEach-Object Name) -join ',')

    $cm = Connect-Ldap "t1510-mon@$($dom.DNSRoot)" $passMon
    $cn = Connect-Ldap "t1510-none@$($dom.DNSRoot)" $passNone
    $ca = Connect-Ldap $null $null
    $cs = $null; try { $cs = Connect-Ldap "svc-activediq@$($dom.DNSRoot)" $SvcPassword } catch { Say 'BIND', 'svc-activediq', (Get-Err $_) }

    # State 0: nobody has the right. State 1: t1510-mon holds Monitor-Topology on the domain head only.
    Read-Repl 'administrator' 'S0_no_grants' $ca
    Read-Repl 't1510-none' 'S0_no_grants' $cn
    Read-Repl 't1510-mon' 'S0_no_grants' $cm
    if ($cs) { Read-Repl 'svc-activediq' 'S0_no_grants' $cs }
    Grant-Monitor $mon.SID $head $rights
    Say 'GRANT', 'domainHead', 'Monitor-Topology only', (Get-AclHash $head)
    Read-Repl 't1510-mon' 'S1_right_on_domain_head' $cm
    Read-Repl 't1510-none' 'S1_right_on_domain_head' $cn
    if ($cs) { Read-Repl 'svc-activediq' 'S1_right_on_domain_head' $cs }
    # State 2: the same right on the configuration and schema heads too (reconnects so the token/ACL are re-evaluated).
    Grant-Monitor $mon.SID $cfg $rights; Grant-Monitor $mon.SID $sch $rights
    $cm2 = Connect-Ldap "t1510-mon@$($dom.DNSRoot)" $passMon
    Read-Repl 't1510-mon' 'S2_right_on_all_heads' $cm2

    # DirSync (rule 7). Baselines first, then the change set, then the delta, for the same four principals.
    $live = New-ADUser -Name 't1510-live' -SamAccountName 't1510-live' -Path $ou -Enabled $false -PassThru
    $victim = New-ADUser -Name 't1510-victim' -SamAccountName 't1510-victim' -Path $ou -Enabled $false -PassThru
    $liveG = $live.ObjectGUID.ToString(); $victimG = $victim.ObjectGUID.ToString()
    Say 'DSYNC', 'objects', "live=$liveG", "victim=$victimG"
    $conns = [ordered]@{ 'administrator' = $ca; 't1510-none' = $cn; 't1510-mon' = $cm2 }
    if ($cs) { $conns['svc-activediq'] = $cs }
    $cookies = @{}
    foreach ($k in $conns.Keys) {
        $r = Invoke-DirSync $conns[$k] $null
        if ($r.error) { Say 'DSYNC', $k, 'baseline', 'error', $r.error; continue }
        $cookies[$k] = $r.cookie
        $sawVictim = @($r.entries | Where-Object { (Guid-Of $_) -eq $victimG }).Count
        $byDn = @($r.entries | Where-Object { $_.DistinguishedName -like 'CN=t1510-*' }).Count
        $withG = @($r.entries | Where-Object { $_.Attributes.Contains('objectGUID') }).Count
        Say 'DSYNC', $k, 'baseline', "entries=$($r.entries.Count)", "with_guid=$withG", "t1510_objects_by_dn=$byDn", "sees_victim=$sawVictim", "cookie_bytes=$(@($r.cookie).Count)"
    }
    # The initial DirSync snapshot lags recent creations (even for Administrator), so a principal's feed must have
    # delivered the victim as a live object before it is deleted. Poll the feed on that condition (bounded to 5 polls), and record it; on dc1 it never became visible (see the T-1510 log).
    foreach ($k in @($cookies.Keys)) {
        $polls = 0; $vis = 0
        while ($polls -lt 5 -and -not $vis) {
            $polls++
            $r = Invoke-DirSync $conns[$k] $cookies[$k]
            if ($r.error) { break }
            $cookies[$k] = $r.cookie
            $vis = [int]@($r.entries | Where-Object { (Guid-Of $_) -eq $victimG }).Count -gt 0
            if (-not $vis) { Start-Sleep -Seconds 1 }
        }
        Say 'DSYNC', $k, 'precheck', "victim_visible_before_delete=$([int]$vis)", "polls=$polls"
    }
    Set-ADUser $live -Description 't1510 change'
    Remove-ADUser $victim -Confirm:$false
    foreach ($k in $cookies.Keys) {
        $r = Invoke-DirSync $conns[$k] $cookies[$k]
        if ($r.error) { Say 'DSYNC', $k, 'delta', 'error', $r.error; continue }
        $liveSeen = 0; $delSeen = 0; $isDel = ''; $wc = ''; $origin = 'none'; $meta = 'not_returned'
        foreach ($e in $r.entries) {
            $g = Guid-Of $e
            if ($g -eq $liveG) { $liveSeen = 1 }
            if ($g -eq $victimG) {
                $delSeen = 1
                if ($e.Attributes.Contains('isDeleted')) { $isDel = $e.Attributes['isDeleted'].GetValues([string])[0] }
                if ($e.Attributes.Contains('whenChanged')) { $wc = $e.Attributes['whenChanged'].GetValues([string])[0] }
                if ($e.Attributes.Contains('msDS-ReplAttributeMetaData')) {
                    $meta = 'returned'
                    $x = ($e.Attributes['msDS-ReplAttributeMetaData'].GetValues([string]) | Where-Object { $_ -match '<pszAttributeName>isDeleted<' }) -join ''
                    if ($x -match '<ftimeLastOriginatingChange>([^<]+)<') { $origin = $Matches[1] }
                }
            }
        }
        Say 'DSYNC', $k, 'delta', "entries=$($r.entries.Count)", "live_change_seen=$liveSeen", "delete_seen=$delSeen", "isDeleted=$isDel", "whenChanged=$wc", "origin_time=$origin", "replattrmeta=$meta"
    }
} finally {
    foreach ($d in $head, $cfg, $sch) { if ($mon) { try { Revoke-All $mon.SID $d } catch { Say 'CLEAN', 'revoke_error', $d, $_.Exception.Message } } }
    if ($created) {
        try { Get-ADOrganizationalUnit $ou | Set-ADObject -ProtectedFromAccidentalDeletion $false; Remove-ADOrganizationalUnit $ou -Recursive -Confirm:$false } catch { Say 'CLEAN', 'ou_error', $_.Exception.Message }
    }
    foreach ($d in $head, $cfg, $sch) { Say 'CLEAN', 'dacl_restored', $d, ([bool]((Get-AclHash $d) -eq $before[$d])) }
    Say 'CLEAN', 'ou_gone', (-not [bool](Get-ADOrganizationalUnit -Filter { Name -eq 'T1510-Lab' } -SearchBase $head -SearchScope OneLevel))
}
Write-Output 'DONE'
