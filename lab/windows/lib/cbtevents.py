"""The DC-side half of the channel-binding acceptance (T-0148, TM-TB3-T3): which Directory Service events did dc1 log in a window.

Pure functions (build the query, parse its output, judge the result) so `gssapi-lab accept` and the offline tests share one
definition. Nothing here talks to a network. The WinRM transport is dc1winrm.py.

Acceptance: with LDAP signing required (LDAPServerIntegrity=2) and channel binding Always (LdapEnforceChannelBindingTokens=2),
the connector's SASL binds over TLS succeed and the DC logs none of MUST_BE_ABSENT in the window of those binds. The control
(a deliberately wrong binding) must make the same query return 3039, otherwise an empty result proves nothing.
"""
import datetime as dt
import re

LOG = "Directory Service"
# The four events the ticket names. Their absence in the window of correct binds is the pass condition.
MUST_BE_ABSENT = (2887, 3039, 3074, 3075)
# Context only (reported, not judged): 2886 DC start with signing not required, 2888 / 2889 signing and unsigned-bind detail,
# 3040 / 3041 channel-binding summary events. https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a
CONTEXT = (2886, 2888, 2889, 3040, 3041)
QUERY_IDS = tuple(sorted(set(MUST_BE_ABSENT) | set(CONTEXT)))
CONTROL_EVENT = 3039  # "failed the channel binding token validation": what a wrong binding must cause under CBT=2


def iso(t):
    """UTC datetime -> the exact string the PowerShell side parses."""
    if t.tzinfo is None:
        raise ValueError("naive datetime: window bounds must be UTC-aware")
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def events_ps(start, end, ids=QUERY_IDS):
    """PowerShell printing one `id|<UTC time>|<message>` line per event of `ids` in [start, end] (UTC datetimes).
    The bounds and ids are formatted from validated values (datetime, int), never from caller text."""
    ids = [int(i) for i in ids]
    return (
        "$s=[DateTime]::Parse('%s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime();"
        "$e=[DateTime]::Parse('%s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime();"
        "Get-WinEvent -FilterHashtable @{LogName='%s';StartTime=$s;EndTime=$e;Id=%s} -EA SilentlyContinue | Sort-Object TimeCreated | "
        "%% { '{0}|{1}|{2}' -f $_.Id,$_.TimeCreated.ToUniversalTime().ToString('o'),(($_.Message -replace '\\s+',' ').Substring(0,[Math]::Min(200,$_.Message.Length))) }"
        % (iso(start), iso(end), LOG, ",".join(str(i) for i in ids)))


_LINE = re.compile(r"^(\d{3,5})\|(\d{4}-\d\d-\d\dT[\d:.]+Z?)\|(.*)$")


def parse(output):
    """-> [(event id, time string, message)] from events_ps output; lines that are not events (WinRM noise) are ignored."""
    out = []
    for line in output.splitlines():
        m = _LINE.match(line.strip())
        if m:
            out.append((int(m.group(1)), m.group(2), m.group(3)))
    return out


def violations(events):
    """Events of MUST_BE_ABSENT present in a window that had only correct, signed, channel-bound binds."""
    return [e for e in events if e[0] in MUST_BE_ABSENT]


def control_seen(events):
    return any(e[0] == CONTROL_EVENT for e in events)


def passed_tests(go_output, names):
    """Names (of `names`) that have a `--- PASS:` line and no `--- FAIL:` line in `go test -v` output. A skipped or absent test is not a pass."""
    ok = []
    for n in names:
        has = lambda word: re.search(r"^\s*--- %s: %s\b" % (word, re.escape(n)), go_output, re.M)
        if has("PASS") and not has("FAIL"):
            ok.append(n)
    return ok
