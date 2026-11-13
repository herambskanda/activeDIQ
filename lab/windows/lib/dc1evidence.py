"""Evidence the live user-search run (T-0765) attaches for QA: what dc1 logged during the run, and what the service
account is a member of. Pure functions (build the PowerShell, parse its output, judge) so the bin and the offline tests
share one definition. The WinRM transport lives in dc1winrm.py. Nothing here prints or stores a credential.

Judging rules (the failing side of each is covered by tests/test_dc1_evidence.py):
  * Directory Service events 2887 (unsigned/clear-text binds summary), 3039 (channel-binding failures) and 3074
    (channel-binding would-be-denied, "when supported" mode) logged inside the run window FAIL the evidence.
  * the service account must not be, directly or through nesting, a member of Domain Admins, Enterprise Admins, Schema
    Admins or the built-in Administrators group (found by well-known SID, so a renamed or localised group still counts).
"""
import re

SVC_SAM = "svc-activediq"
FAIL_EVENT_IDS = (2887, 3039, 3074)
INFO_EVENT_IDS = (2889, 3040, 3041, 3075)  # recorded, not judged: 2889 is the per-client unsigned-bind detail
ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")

NOW_PS = "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')"


def events_ps(since_iso):
    """PowerShell listing `<id>|<time>` for every Directory Service event of interest since a dc1-clock instant."""
    if not ISO.match(since_iso or ""):
        raise ValueError(f"not a UTC ISO-8601 instant: {since_iso!r}")
    ids = ",".join(str(i) for i in FAIL_EVENT_IDS + INFO_EVENT_IDS)
    return ("$s=[datetime]::Parse('%s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal);"
            "Get-WinEvent -FilterHashtable @{LogName='Directory Service';Id=%s;StartTime=$s} -ErrorAction SilentlyContinue |"
            " ForEach-Object { 'EVT|'+$_.Id+'|'+$_.TimeCreated.ToUniversalTime().ToString('o') };'DONE'" % (since_iso, ids))


def parse_events(out):
    """-> {event id: count}. Raises when the DONE marker is missing: a truncated answer must not read as 'no events'."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines or lines[-1] != "DONE":
        raise ValueError("the event query did not finish (no DONE marker)")
    counts = {}
    for l in lines:
        m = re.fullmatch(r"EVT\|(\d+)\|\S+", l)
        if m:
            counts[int(m.group(1))] = counts.get(int(m.group(1)), 0) + 1
    return counts


def event_problems(counts):
    return [f"Directory Service event {i} logged {counts[i]}x during the run" for i in FAIL_EVENT_IDS if counts.get(i)]


# Well-known privileged groups by SID: domain RIDs 512 (Domain Admins), 518 (Schema Admins), 519 (Enterprise Admins)
# and the built-in Administrators S-1-5-32-544.
def groups_ps():
    return ("Import-Module ActiveDirectory;$d=(Get-ADDomain).DomainSID.Value;$root=(Get-ADDomain).Forest;"
            "$u=Get-ADUser -Identity '%s' -Properties MemberOf,Enabled;"
            "'USER|'+$u.DistinguishedName+'|enabled='+$u.Enabled;"
            "foreach($g in $u.MemberOf){'MEMBEROF|'+$g};"
            "foreach($sid in ($d+'-512'),($d+'-518'),($d+'-519'),'S-1-5-32-544'){"
            "$grp=Get-ADGroup -Identity $sid;"
            "$hit=@(Get-ADGroupMember -Identity $grp -Recursive | Where-Object {$_.SamAccountName -eq '%s'}).Count;"
            "'PRIV|'+$grp.Name+'|'+$sid+'|'+$hit};'DONE'" % (SVC_SAM, SVC_SAM))


def parse_groups(out):
    """-> (direct member-of DNs, [(group name, sid, is_member)]). Raises on a truncated answer or no PRIV rows."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines or lines[-1] != "DONE":
        raise ValueError("the group query did not finish (no DONE marker)")
    member_of = [l.split("|", 1)[1] for l in lines if l.startswith("MEMBEROF|")]
    priv = []
    for l in lines:
        m = re.fullmatch(r"PRIV\|(.+)\|(S-1-[\d-]+)\|(\d+)", l)
        if m:
            priv.append((m.group(1), m.group(2), int(m.group(3)) > 0))
    if len(priv) != 4:
        raise ValueError(f"expected 4 privileged-group rows, got {len(priv)}")
    return member_of, priv


def group_problems(priv):
    return [f"{SVC_SAM} is a member of {n} ({sid})" for n, sid, hit in priv if hit]
