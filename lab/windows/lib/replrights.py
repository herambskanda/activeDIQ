"""T-1510: build, parse and judge the msDS-Repl* / DirSync rights run on dc1 (TM-D31 rules 3 and 7, threat-model §6.3).
Pure functions: the PowerShell is guest/repl-rights.ps1, the transport is dc1winrm.py, the driver is bin/repl-rights-lab.
Nothing here prints or stores a credential. The judging is deliberately conservative: an empty answer is never read as
"right sufficient" or "right denied" unless the Administrator control on the same DC returned values (a single-DC lab
returns nothing to anyone, so emptiness alone proves nothing)."""
import os, re

ATTRS = ("msDS-ReplAllInboundNeighbors", "msDS-ReplPendingOps", "msDS-ReplConnectionFailures", "msDS-ReplLinkFailures")
PRIVILEGED = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Replicator", "Backup Operators",
              "Server Operators", "Account Operators", "Domain Controllers", "Enterprise Domain Controllers")
GUEST_PS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guest", "repl-rights.ps1")


REMOTE_PS1 = "C:\\Windows\\Temp\\t1510-repl-rights.ps1"


def guest_bytes():
    with open(GUEST_PS, "rb") as f:
        return f.read()


def run_command(svc_password, path=REMOTE_PS1):
    """The short WinRM command: the password goes in a process environment variable (single-quoted literal), never into the
    uploaded file, and the file is removed afterwards by the caller."""
    if not svc_password or any(c in svc_password for c in "\r\n\x00"):
        raise ValueError("WIN_LAB_SVC_PASSWORD is missing or contains a line break")
    return "$env:T1510_SVC='%s'; & '%s'; $rc=$LASTEXITCODE; Remove-Item '%s' -Force -ErrorAction SilentlyContinue" % (
        svc_password.replace("'", "''"), path, path)


def parse(out):
    """-> dict(setup, reads, dsync, clean, binds). Raises ValueError when DONE is missing (a truncated run proves nothing)."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if not lines or lines[-1] != "DONE":
        raise ValueError("the run did not finish (no DONE marker)")
    r = {"setup": {}, "reads": {}, "dsync": {}, "clean": {}, "binds": {}, "objects": {}}
    for l in lines[:-1]:
        f = l.split("|")
        tag = f[0]
        if tag == "SETUP" and len(f) >= 3:
            r["setup"][f[1]] = f[2]
        elif tag == "READ" and len(f) >= 6:
            row = {"kind": f[4]}
            if f[4] == "entry":
                row["sentinel"] = f[5] == "sentinel=True"
                row["returned"] = int(f[6].split("=")[1])
                row["detail"] = f[7] if len(f) > 7 else ""
            else:
                row["detail"] = f[5]
            r["reads"][(f[1], f[2], f[3])] = row
        elif tag == "DSYNC" and len(f) >= 4:
            if f[1] == "objects":
                r["objects"] = dict(x.split("=", 1) for x in f[2:])
            else:
                row = {"error": f[3] == "error"}
                if row["error"]:
                    row["detail"] = f[4]
                else:
                    row.update(dict(x.split("=", 1) for x in f[3:] if "=" in x))
                r["dsync"][(f[1], f[2])] = row
        elif tag == "CLEAN":
            r["clean"][f[1] + (":" + f[2] if f[1] == "dacl_restored" else "")] = f[-1]
        elif tag == "BIND":
            r["binds"][f[1]] = f[2]
    return r


def _returned(r, principal, state):
    """-> {base: attrs returned} for entries that came back; errors map to None."""
    return {b: (v.get("returned") if v["kind"] == "entry" else None)
            for (p, s, b), v in r["reads"].items() if p == principal and s == state}


def conclusions(r):
    """-> (facts, problems). Problems make the run fail; facts are what the log records (some are 'inconclusive')."""
    facts, bad = {}, []
    for who in ("t1510-mon", "t1510-none"):
        groups = r["setup"].get(who.replace("t1510-", "") + "_memberOf", "")
        for g in PRIVILEGED:
            if g in [x.strip() for x in groups.split(",")]:
                bad.append(f"{who} is a member of {g}: the run no longer tests 'only the replication-monitoring right'")
    for k, v in r["clean"].items():
        if k.startswith("dacl_restored:") and v != "True":
            bad.append(f"partition head DACL not restored ({k.split(':', 1)[1]})")
        if k == "ou_gone" and v != "True":
            bad.append("OU=T1510-Lab was not removed")
        if k.endswith("_error"):
            bad.append(f"cleanup error: {k}")
    # the no-right principal must get an entry back (attribute-less or not), never an error (T-0404, TM-D31 rule 4)
    for (p, s, b), v in sorted(r["reads"].items()):
        if p == "t1510-none" and v["kind"] != "entry":
            bad.append(f"no-right read at {b} ({s}) returned {v['kind']} {v['detail']}, expected an attribute-less entry")
        if p == "t1510-none" and v["kind"] == "entry" and not v["sentinel"]:
            bad.append(f"no-right read at {b} returned an entry with no attributes at all")
    admin = _returned(r, "administrator", "S0_no_grants")
    loc = sorted(b for b, n in admin.items() if n)
    facts["administrator_locations"] = loc
    facts["conclusive"] = bool(loc)
    if not loc:
        facts["location"] = ("INCONCLUSIVE: the Administrator control returned none of the four attributes at any base "
                             "(rootDSE, domain head, configuration head, schema head, NTDS Settings); on a DC with no "
                             "replication partners an empty answer cannot be told from a denied one")
        facts["mon_right_sufficient"] = None
        facts["no_right_gets_values"] = None
    else:
        facts["location"] = ", ".join(loc)
        mon = _returned(r, "t1510-mon", "S1_right_on_domain_head")
        facts["mon_right_sufficient"] = all((mon.get(b) or 0) >= admin[b] for b in loc)
        facts["mon_needs_wider_heads"] = (not facts["mon_right_sufficient"]) and all(
            (_returned(r, "t1510-mon", "S2_right_on_all_heads").get(b) or 0) >= admin[b] for b in loc)
        facts["no_right_gets_values"] = any((n or 0) > 0 for n in _returned(r, "t1510-none", "S0_no_grants").values())
        if facts["no_right_gets_values"]:
            bad.append("the no-right principal received msDS-Repl* values: the right is not what gates them (TM-D31 rule 3 premise is wrong)")
    ds = {}
    for (p, ph), v in r["dsync"].items():
        if ph == "delta":
            ds[p] = dict(v, victim_visible_before_delete=r["dsync"].get((p, "precheck"), {}).get("victim_visible_before_delete", "?"))
        if ph == "baseline" and v["error"]:
            ds.setdefault(p, v)
    facts["dirsync"] = ds
    return facts, bad


def render(r, facts, problems, started, finished):
    """Markdown body for the run log."""
    o = ["| Principal | State | rootDSE | domain head | config head | schema head | NTDS Settings |", "| --- | --- | --- | --- | --- | --- | --- |"]
    cols = ("rootDSE", "domainHead", "configHead", "schemaHead", "ntdsSettings")
    for p, s in sorted({(p, s) for (p, s, _b) in r["reads"]}, key=lambda x: (x[1], x[0])):
        cells = []
        for b in cols:
            v = r["reads"].get((p, s, b))
            cells.append("-" if v is None else (f"error {v['detail']}" if v["kind"] != "entry" else f"entry, {v['returned']}/4 attrs"))
        o.append(f"| {p} | {s} | " + " | ".join(cells) + " |")
    o += ["", "| Principal | victim visible before delete | live change seen | delete seen | isDeleted | whenChanged | originating time | msDS-ReplAttributeMetaData |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for p, v in facts["dirsync"].items():
        if v["error"]:
            o.append(f"| {p} | error {v.get('detail')} | | | | | | |")
        else:
            o.append(f"| {p} | {v['victim_visible_before_delete']} | {v['live_change_seen']} | {v['delete_seen']} | {v['isDeleted'] or '-'} | {v['whenChanged'] or '-'} | {v['origin_time']} | {v['replattrmeta']} |")
    return "\n".join(o)
