#!/usr/bin/env python3
"""Deterministic, synthetic organisation generator for the activeDIQ AD lab (T-0012).

Same --seed, --tier and --now  =>  byte-identical output (checked by lab/tests/test_generate.py).
Emits LDIF for `ldbadd` / `ldbmodify` against a *stopped* Samba sam.ldb, plus manifest.json
(expected counts, asserted against the live directory by lab/tests/verify.sh).

Test-only fixture generator: it builds DNs with a small RFC 4514 escaper because it writes static
fixtures into a lab database. Product code must never do this — it uses the safe DN builders
(ADR-0001, knowledge/development/architecture/safe-primitives.md).

Everything is synthetic: names come from the fixed lists below, mail is @example.com, and the
organisation is invented. No real people, partners or customers.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import sys
import time
from pathlib import Path

GENERATOR_VERSION = "1"

BASE_DN = "DC=lab,DC=activediq,DC=test"
UPN_SUFFIX = "lab.activediq.test"
MAIL_DOMAIN = "example.com"
COMPANY = "Example Corp"

FIRST = """Ada Alan Amir Anika Arjun Beatrice Bruno Camila Carlos Chen Clara Dara David Diego Dmitri
Elena Elias Emre Farah Felix Fiona Gabriel Grace Hana Hassan Hector Ida Imani Ingrid Ivan Jamal
Jana Jasper Jin Joaquin Kai Kamala Karim Katya Kofi Lars Layla Leon Lina Luca Mai Marco Maya
Mehmet Mina Nadia Nikhil Nora Omar Olga Pablo Priya Quentin Rahul Rosa Sade Samir Sofia Tariq
Tessa Thabo Uma Vera Viktor Wen Xavier Yara Yusuf Zara Zoltan""".split()
LAST = """Abara Adler Alvarez Andersson Banerjee Barros Becker Bianchi Castillo Chaudhry Costa Dahl
Dubois Eze Farouk Fischer Fontaine Garcia Gupta Haddad Hansen Hoang Ibarra Ito Jovanovic Kaplan
Khan Kowalski Kruger Larsen Lindqvist Lopez Mahlangu Marino Mbeki Mendes Morales Nakamura Naidoo
Novak Okafor Olsen Ortiz Pappas Park Petrov Quinn Rahman Rossi Saito Santos Schmidt Sharma
Silva Singh Sorensen Tanaka Torres Ueda Varga Vasquez Weber Yamada Zhang Ziegler Zubiri Abe
Ansah Bauer Cruz""".split()

# (OU name, weight, title pool)
DEPARTMENTS = [
    ("Engineering", 22, ["Software Engineer", "Senior Engineer", "QA Engineer", "SRE", "Engineering Manager"]),
    ("Sales", 14, ["Account Executive", "Sales Engineer", "SDR", "Regional Sales Lead"]),
    ("Support", 12, ["Support Specialist", "Support Engineer", "Escalation Lead"]),
    ("Finance", 6, ["Accountant", "Financial Analyst", "Controller"]),
    ("HumanResources", 4, ["HR Partner", "Recruiter", "Benefits Specialist"]),
    ("Marketing", 7, ["Content Strategist", "Designer", "Marketing Manager"]),
    ("Operations", 9, ["Operations Analyst", "Logistics Coordinator", "Facilities Lead"]),
    ("Legal", 2, ["Counsel", "Paralegal", "Compliance Officer"]),
    ("IT", 5, ["Systems Administrator", "Service Desk Analyst", "Network Engineer"]),
    ("Product", 5, ["Product Manager", "Product Designer", "Researcher"]),
    ("Manufacturing", 8, ["Technician", "Line Supervisor", "Quality Inspector"]),
    ("Executive", 1, ["Director", "VP", "Chief of Staff"]),
    ("Procurement", 3, ["Buyer", "Vendor Manager"]),
    ("Research", 2, ["Scientist", "Lab Technician"]),
]
OFFICES = ["Northgate", "Riverside", "Eastfield", "Lakeview", "Hillcrest", "Southport"]

# tier -> (users, computers, servers, big_group_members, empty_ous)
TIERS = {
    "small": dict(users=300, computers=60, servers=8, big_group=3000, empty_ous=3),
    "standard": dict(users=5000, computers=1500, servers=40, big_group=3000, empty_ous=12),
}

# user states, as shares of generated users (applied by index from a seeded shuffle)
STATE_SHARES = [
    ("disabled", 0.03),
    ("stale", 0.08),            # enabled, no logon for 180-900 days
    ("expired_account", 0.02),  # accountExpires in the past
    ("expiring_soon", 0.01),    # accountExpires within 30 days
    ("never_expires", 0.02),    # DONT_EXPIRE_PASSWORD
    ("must_change", 0.005),     # pwdLastSet = 0
    ("pwd_expired", 0.02),      # password older than the 90-day lab max age
    ("pwd_expiring", 0.02),     # password 80-89 days old
    ("never_logged_on", 0.02),  # enabled, lastLogon absent
]
LOCKED_COUNT = {"small": 6, "standard": 25}

UAC_NORMAL = 512
UAC_DISABLED = 514
UAC_NORMAL_NEVER_EXPIRES = 66048
UAC_WORKSTATION = 4096

GT_GLOBAL_SECURITY = -2147483646
GT_DOMAIN_LOCAL_SECURITY = -2147483644
GT_UNIVERSAL_SECURITY = -2147483640
GT_GLOBAL_DISTRIBUTION = 2


def esc_dn(value: str) -> str:
    """RFC 4514 escape of an attribute value for use in a DN (lab fixtures only)."""
    out = []
    for i, ch in enumerate(value):
        if ch in ',+"\\<>;=' or (i == 0 and ch in " #") or (i == len(value) - 1 and ch == " "):
            out.append("\\" + ch)
        elif ord(ch) < 0x20:
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def filetime(unix_seconds: int) -> int:
    return (unix_seconds + 11644473600) * 10_000_000


class B64(str):
    """A value that is already base64 (emitted with `::`)."""


def ldif_value(name: str, value) -> str:
    if isinstance(value, B64):
        return f"{name}:: {value}"
    s = str(value)
    safe = (
        s.isascii() and s.isprintable() and s[:1] not in " :<" and s[-1:] != " "
    ) if s else True
    if safe:
        return f"{name}: {s}"
    return f"{name}:: {base64.b64encode(s.encode('utf-8')).decode('ascii')}"


class Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def entry(self, dn: str, attrs: list[tuple[str, object]]) -> None:
        self.lines.append(ldif_value("dn", dn))
        for k, v in attrs:
            if v is None:
                continue
            self.lines.append(ldif_value(k, v))
        self.lines.append("")

    def modify_add(self, dn: str, attr: str, values: list[str]) -> None:
        self.lines.append(ldif_value("dn", dn))
        self.lines.append("changetype: modify")
        self.lines.append(f"add: {attr}")
        for v in values:
            self.lines.append(ldif_value(attr, v))
        self.lines.append("")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def pwd_attr(password: str) -> B64:
    return B64(base64.b64encode(('"%s"' % password).encode("utf-16-le")).decode("ascii"))


def generate(tier: str, seed: int, now: int, user_pw: str, svc_pw: str) -> tuple[dict[str, str], dict]:
    cfg = TIERS[tier]
    rng = random.Random(f"activediq-lab/{GENERATOR_VERSION}/{tier}/{seed}")
    day = 86400

    # Samba only accepts pwdLastSet 0 or -1 over LDAP/ldb, so password ages are produced by adding
    # each user while the clock (libfaketime in the lab container) reads the wanted password-set day.
    # Hence users and computers are bucketed by age, one LDIF per bucket (loadplan.txt).
    objs = Writer()   # OUs, service account, edge-case users (ldbadd, real clock)
    aged: dict[int, Writer] = {}   # age in days -> users/computers added with the clock set back
    grps = Writer()   # groups, no members      (ldbadd)
    attrs_w = Writer()  # lastLogon, accountExpires, manager… (ldbmodify)
    mems = Writer()   # memberships             (ldbmodify)

    def aged_writer(age_days: int) -> Writer:
        return aged.setdefault(age_days, Writer())

    def step(lo: int, hi: int, stp: int) -> int:
        return lo + stp * rng.randint(0, (hi - lo) // stp)
    manifest: dict = {"generator_version": GENERATOR_VERSION, "tier": tier, "seed": seed, "now": now}
    counts = {k: 0 for k in ["users", "computers", "groups", "ous"]}

    def add_ou(name: str, parent: str) -> str:
        dn = f"OU={esc_dn(name)},{parent}"
        objs.entry(dn, [("objectClass", "top"), ("objectClass", "organizationalUnit"),
                        ("ou", name), ("description", f"activeDIQ lab: {name}")])
        counts["ous"] += 1
        return dn

    managed = add_ou("Managed", BASE_DN)
    svc_ou = add_ou("ServiceAccounts", BASE_DN)
    servers_ou = add_ou("Servers", managed)
    edge_ou = add_ou("EdgeCases", managed)
    dept_ous: dict[str, dict[str, str]] = {}
    for dept, _, _ in DEPARTMENTS:
        d = add_ou(dept, managed)
        dept_ous[dept] = {
            "dept": d,
            "users": add_ou("Users", d),
            "computers": add_ou("Computers", d),
            "groups": add_ou("Groups", d),
        }
        dept_ous[dept]["contractors"] = add_ou("Contractors", dept_ous[dept]["users"])
    for i in range(cfg["empty_ous"]):
        add_ou(f"Empty-{i + 1:02d}", managed)
    add_ou("Ops, Field", managed)          # comma in an OU name
    add_ou("Sales #Q4+Plan", managed)       # '#' and '+' in an OU name

    # ---- service account (outside Managed so it cannot edit itself) ------------------------
    svc_dn = f"CN=svc-activediq,{svc_ou}"
    objs.entry(svc_dn, [
        ("objectClass", "top"), ("objectClass", "person"), ("objectClass", "organizationalPerson"),
        ("objectClass", "user"), ("cn", "svc-activediq"), ("sAMAccountName", "svc-activediq"),
        ("userPrincipalName", f"svc-activediq@{UPN_SUFFIX}"), ("displayName", "activeDIQ lab service account"),
        ("description", "Delegated to OU=Managed only (never Domain Admins)"),
        ("userAccountControl", UAC_NORMAL_NEVER_EXPIRES), ("unicodePwd", pwd_attr(svc_pw)),
    ])

    # ---- people ---------------------------------------------------------------------------
    pairs = [(f, l) for f in FIRST for l in LAST]
    rng.shuffle(pairs)
    if cfg["users"] > len(pairs):
        raise SystemExit(f"tier needs {cfg['users']} unique names, only {len(pairs)} available")

    # department assignment by weight
    total_w = sum(w for _, w, _ in DEPARTMENTS)
    assign: list[int] = []
    for idx, (_, w, _) in enumerate(DEPARTMENTS):
        assign += [idx] * max(1, round(cfg["users"] * w / total_w))
    while len(assign) < cfg["users"]:
        assign.append(0)
    assign = assign[: cfg["users"]]
    rng.shuffle(assign)

    # state assignment
    order = list(range(cfg["users"]))
    rng.shuffle(order)
    state_of: dict[int, str] = {}
    pos = 0
    state_counts: dict[str, int] = {}
    for name, share in STATE_SHARES:
        n = max(2, round(cfg["users"] * share))
        for i in order[pos:pos + n]:
            state_of[i] = name
        state_counts[name] = n
        pos += n
    # the first user in every department is its manager and always plain
    seen_dept: set[int] = set()
    dept_managers: dict[str, str] = {}
    sam_used: set[str] = set()
    users: list[dict] = []
    for i in range(cfg["users"]):
        first, last = pairs[i]
        dept, _, titles = DEPARTMENTS[assign[i]]
        is_manager = assign[i] not in seen_dept
        if is_manager:
            seen_dept.add(assign[i])
            state_of.pop(i, None)
        contractor = (not is_manager) and rng.random() < 0.05
        ou = dept_ous[dept]["contractors" if contractor else "users"]
        cn = f"{first} {last}"
        sam = f"{first}.{last}".lower()[:20]
        n = 1
        while sam in sam_used:
            n += 1
            sam = f"{first}.{last}".lower()[: 20 - len(str(n))] + str(n)
        sam_used.add(sam)
        users.append(dict(i=i, first=first, last=last, cn=cn, sam=sam, dept=dept, ou=ou,
                          dn=f"CN={esc_dn(cn)},{ou}", title=titles[0] if is_manager else rng.choice(titles),
                          manager=is_manager, contractor=contractor, state=state_of.get(i, "normal")))
        if is_manager:
            dept_managers[dept] = users[-1]["dn"]
    state_counts = {}
    for u in users:
        state_counts[u["state"]] = state_counts.get(u["state"], 0) + 1

    locked_pool = [u for u in users if u["state"] == "normal" and not u["manager"]]
    locked = [u["sam"] for u in rng.sample(locked_pool, LOCKED_COUNT[tier])]
    manifest["locked_samaccountnames"] = sorted(locked)

    for u in users:
        st = u["state"]
        uac = UAC_NORMAL
        pwd_age: int | None = rng.randint(1, 60)    # None => pwdLastSet 0 (must change at next logon)
        last_logon: int | None = now - rng.randint(0, 29) * day
        expires = 0
        if st == "disabled":
            uac = UAC_DISABLED
            last_logon = now - rng.randint(30, 400) * day
        elif st == "stale":
            lla = rng.randint(180, 900)
            last_logon = now - lla * day
            pwd_age = ((lla + 15) // 15) * 15
        elif st == "expired_account":
            expires = now - rng.randint(1, 365) * day
        elif st == "expiring_soon":
            expires = now + rng.randint(1, 30) * day
        elif st == "never_expires":
            uac = UAC_NORMAL_NEVER_EXPIRES
            pwd_age = step(200, 1500, 50)
        elif st == "must_change":
            pwd_age = None
            last_logon = None
        elif st == "pwd_expired":
            pwd_age = step(100, 300, 10)
        elif st == "pwd_expiring":
            pwd_age = rng.randint(80, 89)
        elif st == "never_logged_on":
            last_logon = None
        u["uac"] = uac
        u["pwd_age"] = pwd_age
        office = OFFICES[rng.randrange(len(OFFICES))]
        u["_mgr_dept"] = None if u["manager"] else u["dept"]
        entry_attrs = [
            ("objectClass", "top"), ("objectClass", "person"), ("objectClass", "organizationalPerson"),
            ("objectClass", "user"), ("cn", u["cn"]), ("givenName", u["first"]), ("sn", u["last"]),
            ("displayName", u["cn"]), ("sAMAccountName", u["sam"]),
            ("userPrincipalName", f"{u['sam']}@{UPN_SUFFIX}"),
            ("mail", f"{u['sam']}@{MAIL_DOMAIN}"), ("department", u["dept"]), ("company", COMPANY),
            ("title", u["title"]), ("physicalDeliveryOfficeName", office),
            ("telephoneNumber", f"+1-555-{rng.randint(0, 9999):04d}"),
            ("employeeID", f"E{100000 + u['i']}"),
            ("employeeType", "Contractor" if u["contractor"] else "Employee"),
            ("description", f"lab user state={st}"),
            ("userAccountControl", uac),
            ("pwdLastSet", 0 if pwd_age is None else None),
            ("unicodePwd", pwd_attr(user_pw)),
        ]
        aged_writer(pwd_age or 0).entry(u["dn"], entry_attrs)
        mods = [("accountExpires", filetime(expires) if expires else None),
                ("lastLogon", filetime(last_logon) if last_logon else None),
                ("lastLogonTimestamp", filetime(last_logon) if last_logon else None),
                ("logonCount", rng.randint(1, 4000) if last_logon else None)]
        mods = [(k, v) for k, v in mods if v is not None]
        if mods:
            attrs_w.lines.append(ldif_value("dn", u["dn"]))
            attrs_w.lines.append("changetype: modify")
            for k, v in mods:
                attrs_w.lines += [f"replace: {k}", ldif_value(k, v), "-"]
            attrs_w.lines.append("")
        counts["users"] += 1

    # ---- edge-case people (names that break naive code) --------------------------------------
    edge_specs = [
        ("Smith, John", "ecomma", "Comma in CN"),
        ("#Hash Lead", "ehash", "Leading # in CN"),
        ("Plus+Sign", "eplus", "Plus in CN"),
        ('Quote "Q" User', "equote", "Double quotes in CN"),
        ("Back\\slash User", "ebackslash", "Backslash in CN"),
        ("Angle<Brackets>;Semi=Eq", "eangle", "<>;= in CN"),
        ("Paren (Star*) User", "estar", "Parentheses and asterisk (LDAP filter specials)"),
        ("José Müller", "ejose", "Latin accents (NFC)"),
        ("José Nüll", "enfd", "Latin accents (NFD / combining marks)"),
        ("山田 太郎", "eyamada", "CJK"),
        ("Zoë 😀 Emoji 𝒰", "eemoji", "non-BMP (surrogate pairs)"),
        ("Ünïcödé Ñame", "enfc2", "Mixed accents"),
        ("A" * 64, "e64cn", "64-character CN (max)"),
        ("Twenty Char Sam", "abcdefghij1234567890", "20-character sAMAccountName (max)"),
        ("Dotted.Hyphen-Name", "dotted.hyphen-name", "Dot and hyphen in sAMAccountName"),
        ("Trailing Space ", "etrail", "Trailing space in CN"),
        (" Leading Space", "elead", "Leading space in CN"),
    ]
    manifest["edge_users"] = []
    for cn, sam, desc in edge_specs:
        dn = f"CN={esc_dn(cn)},{edge_ou}"
        objs.entry(dn, [
            ("objectClass", "top"), ("objectClass", "person"), ("objectClass", "organizationalPerson"),
            ("objectClass", "user"), ("cn", cn), ("sn", cn[:32].strip() or "x"), ("displayName", cn.strip()),
            ("sAMAccountName", sam), ("userPrincipalName", f"{sam}@{UPN_SUFFIX}"),
            ("mail", f"{sam}@{MAIL_DOMAIN}"), ("description", f"edge case: {desc}"),
            ("userAccountControl", UAC_NORMAL),
            ("unicodePwd", pwd_attr(user_pw)),
        ])
        counts["users"] += 1
        manifest["edge_users"].append({"cn": cn, "sam": sam, "dn": dn})

    # ---- computers --------------------------------------------------------------------------
    comp_state = {"stale": 0, "disabled": 0}
    for i in range(cfg["computers"]):
        dept = DEPARTMENTS[rng.choices(range(len(DEPARTMENTS)), weights=[d[1] for d in DEPARTMENTS])[0]][0]
        name = f"WS-{dept[:4].upper()}-{i + 1:04d}"
        kind = rng.random()
        uac, age = UAC_WORKSTATION, rng.randint(1, 20)
        if kind < 0.03:
            uac, comp_state["disabled"] = UAC_WORKSTATION | 2, comp_state["disabled"] + 1
        elif kind < 0.13:
            age, comp_state["stale"] = step(120, 700, 20), comp_state["stale"] + 1
        aged_writer(age).entry(f"CN={name},{dept_ous[dept]['computers']}", [
            ("objectClass", "top"), ("objectClass", "person"), ("objectClass", "organizationalPerson"),
            ("objectClass", "user"), ("objectClass", "computer"), ("cn", name),
            ("sAMAccountName", name + "$"), ("dNSHostName", f"{name.lower()}.{UPN_SUFFIX}"),
            ("operatingSystem", rng.choice(["Windows 11 Enterprise", "Windows 10 Enterprise"])),
            ("userAccountControl", uac),
        ])
        attrs_w.lines += [ldif_value("dn", f"CN={name},{dept_ous[dept]['computers']}"), "changetype: modify",
                          "replace: lastLogon", ldif_value("lastLogon", filetime(now - age * day)), "-",
                          "replace: lastLogonTimestamp", ldif_value("lastLogonTimestamp", filetime(now - age * day)), ""]
        counts["computers"] += 1
    server_names: list[str] = []
    for i in range(cfg["servers"]):
        name = f"SRV-{['APP', 'DB', 'FILE', 'WEB'][i % 4]}-{i + 1:03d}"
        server_names.append(name)
        aged_writer(rng.randint(1, 20)).entry(f"CN={name},{servers_ou}", [
            ("objectClass", "top"), ("objectClass", "person"), ("objectClass", "organizationalPerson"),
            ("objectClass", "user"), ("objectClass", "computer"), ("cn", name),
            ("sAMAccountName", name + "$"), ("dNSHostName", f"{name.lower()}.{UPN_SUFFIX}"),
            ("operatingSystem", "Windows Server 2022 Standard"), ("userAccountControl", UAC_WORKSTATION),
        ])
        counts["computers"] += 1

    # `manager` is a linked attribute: its target must exist, so it is set after the add pass
    for u in users:
        if u["_mgr_dept"]:
            attrs_w.lines.append(ldif_value("dn", u["dn"]))
            attrs_w.lines += ["changetype: modify", "replace: manager", ldif_value("manager", dept_managers[u["dept"]]), ""]

    # ---- groups ------------------------------------------------------------------------------
    def add_group(name: str, ou: str, gtype: int, desc: str, sam: str | None = None) -> str:
        dn = f"CN={esc_dn(name)},{ou}"
        grps.entry(dn, [("objectClass", "top"), ("objectClass", "group"), ("cn", name),
                        ("sAMAccountName", sam or name), ("groupType", gtype), ("description", desc)])
        counts["groups"] += 1
        return dn

    by_dept: dict[str, list[dict]] = {d: [] for d, _, _ in DEPARTMENTS}
    for u in users:
        by_dept[u["dept"]].append(u)

    org_groups_ou = add_ou("OrgGroups", managed)
    dept_all: list[str] = []
    dept_mgr_groups: list[str] = []
    dept_dl: list[tuple[str, str]] = []
    for dept, _, _ in DEPARTMENTS:
        gou = dept_ous[dept]["groups"]
        g_all = add_group(f"GG-{dept}-All", gou, GT_GLOBAL_SECURITY, f"All {dept} staff")
        g_mgr = add_group(f"GG-{dept}-Managers", gou, GT_GLOBAL_SECURITY, f"{dept} managers")
        g_dl = add_group(f"DL-{dept}-Share-RW", gou, GT_DOMAIN_LOCAL_SECURITY, f"{dept} share, read/write")
        g_dist = add_group(f"DG-{dept}-Announce", gou, GT_GLOBAL_DISTRIBUTION, f"{dept} announcements")
        dept_all.append(g_all)
        dept_mgr_groups.append(g_mgr)
        dept_dl.append((dept, g_dl))
        staff = by_dept[dept]
        mems.modify_add(g_all, "member", [u["dn"] for u in staff])
        mems.modify_add(g_mgr, "member", [u["dn"] for u in staff if u["manager"]])
        mems.modify_add(g_dist, "member", [u["dn"] for u in staff[: max(3, len(staff) // 4)]])
        mems.modify_add(g_dl, "member", [g_all])           # global -> domain local nesting
        # project groups: random subsets, a few dozen members
        for p in range(max(1, len(staff) // 60)):
            g_p = add_group(f"GG-{dept}-Project-{p + 1:02d}", gou, GT_GLOBAL_SECURITY, f"{dept} project {p + 1}")
            k = min(len(staff), rng.randint(5, 40))
            mems.modify_add(g_p, "member", [u["dn"] for u in rng.sample(staff, k)])

    all_staff = add_group("GG-All-Staff", org_groups_ou, GT_UNIVERSAL_SECURITY, "Every department (nested)")
    mems.modify_add(all_staff, "member", dept_all)
    leadership = add_group("GG-Leadership", org_groups_ou, GT_UNIVERSAL_SECURITY, "All managers (nested)")
    mems.modify_add(leadership, "member", dept_mgr_groups)
    # nesting depth: chain of 6
    prev = leadership
    for depth in range(1, 7):
        g = add_group(f"GG-Nest-L{depth}", org_groups_ou, GT_GLOBAL_SECURITY if depth > 1 else GT_UNIVERSAL_SECURITY,
                      f"Nesting depth {depth}")
        mems.modify_add(prev, "member", [g])
        prev = g
    mems.modify_add(prev, "member", [users[1]["dn"]])
    # cycle A -> B -> C -> A  (Windows allows it; membership expansion must terminate)
    ga = add_group("GG-Cycle-A", org_groups_ou, GT_UNIVERSAL_SECURITY, "Circular nesting A")
    gb = add_group("GG-Cycle-B", org_groups_ou, GT_UNIVERSAL_SECURITY, "Circular nesting B")
    gc = add_group("GG-Cycle-C", org_groups_ou, GT_UNIVERSAL_SECURITY, "Circular nesting C")
    mems.modify_add(ga, "member", [gb, users[2]["dn"]])
    mems.modify_add(gb, "member", [gc])
    mems.modify_add(gc, "member", [ga])
    # empty group, huge group (> 1500 values forces ranged retrieval), self-nested chain
    add_group("GG-Empty", org_groups_ou, GT_GLOBAL_SECURITY, "A group with no members")
    big_n = min(cfg["big_group"], len(users))
    big = add_group("GG-Big", org_groups_ou, GT_GLOBAL_SECURITY, f"{big_n} members (ranged retrieval above 1500)")
    mems.modify_add(big, "member", [u["dn"] for u in users[:big_n]])
    # group-name edge cases
    add_group("GG-Edge, Comma #Group+", org_groups_ou, GT_GLOBAL_SECURITY, "Specials in a group CN", sam="GG-Edge-Specials")
    g_uni = add_group("GG-日本語-Ünï", org_groups_ou, GT_GLOBAL_SECURITY, "Unicode group CN", sam="GG-Edge-Unicode")
    mems.modify_add(g_uni, "member", [e["dn"] for e in manifest["edge_users"]])
    # computers group
    g_comp = add_group("GG-Servers", org_groups_ou, GT_GLOBAL_SECURITY, "Server computer accounts")
    mems.modify_add(g_comp, "member", [f"CN={n},{servers_ou}" for n in server_names])

    samples: dict[str, list[dict]] = {}
    for u in users:
        lst = samples.setdefault(u["state"], [])
        if len(lst) < 2:
            lst.append({"sam": u["sam"], "pwd_age_days": u["pwd_age"]})
    manifest["samples"] = samples
    manifest["counts"] = {
        "users": counts["users"],
        "generated_users": cfg["users"],
        "edge_users": len(edge_specs),
        "computers": counts["computers"],
        "groups": counts["groups"],
        "ous": counts["ous"],
        "user_states": state_counts,
        "computer_states": comp_state,
        "big_group_members": big_n,
        "departments": len(DEPARTMENTS),
    }
    manifest["service_account_dn"] = svc_dn
    manifest["managed_ou"] = managed
    files = {"01-objects.ldif": objs.text()}
    plan = [f"0 ldbadd 01-objects.ldif"]
    for age in sorted(aged, reverse=True):
        name = f"10-aged-{age:04d}d.ldif"
        files[name] = aged[age].text()
        # fixed 12:00 UTC on the password-set day; 0 => real clock
        plan.append(f"{(now - age * day + 43200) if age else 0} ldbadd {name}")
    files["20-groups.ldif"] = grps.text()
    files["30-attrs.ldif"] = attrs_w.text()
    files["31-members.ldif"] = mems.text()
    plan += ["0 ldbadd 20-groups.ldif", "0 ldbmodify 30-attrs.ldif", "0 ldbmodify 31-members.ldif"]
    files["loadplan.txt"] = "\n".join(plan) + "\n"
    return files, manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tier", choices=sorted(TIERS), default="standard")
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--now", type=int, default=None,
                    help="reference time (unix seconds) all ages are relative to; default: $LAB_SEED_NOW or current time")
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args(argv)
    now = args.now if args.now is not None else int(os.environ.get("LAB_SEED_NOW") or time.time())
    now -= now % 86400  # whole days, so the same-day rebuild is byte-identical
    user_pw = os.environ.get("LAB_USER_PASSWORD")
    svc_pw = os.environ.get("LAB_SVC_PASSWORD")
    if not user_pw or not svc_pw:
        print("LAB_USER_PASSWORD and LAB_SVC_PASSWORD must be set (generated by `make lab-up`)", file=sys.stderr)
        return 2
    files, manifest = generate(args.tier, args.seed, now, user_pw, svc_pw)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (out / name).write_text(body, encoding="utf-8", newline="\n")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"seed v{GENERATOR_VERSION} tier={args.tier}: " + json.dumps(manifest["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
