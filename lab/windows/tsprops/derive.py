"""Offline: captures.json -> records.jsonl (TSP-W.., corpus shape of safe-primitives §8) + probes.jsonl. No DC needed.

`expect.value` is read from the blob with the reference parser (blob.py) and then CHECKED against what Windows itself returned for the same
object (WTSQueryUserConfig and the ADSI IADsTSUserEx properties ADUC binds to). A mismatch fails the derive: the expectation never rests on our
parser alone. Windows' readers return a lossy ANSI conversion for non-ANSI text, so for those fields only the W twin is the expectation.
"""
import json, os, sys
import blob as B

BITS = {"logon_disabled": 0x00010000, "reconnect_same": 0x00020000, "reset_broken": 0x00040000, "inherit_initial_program": 0x10000000,
        "inherit_shadow": 0x02000000, "inherit_max_connection": 0x01000000, "inherit_max_disconnection": 0x00800000, "inherit_max_idle": 0x00400000}
TEXT = {"CtxInitialProgram": "initial_program", "CtxWorkDirectory": "work_directory", "CtxWFHomeDir": "home_dir", "CtxWFHomeDirDrive": "home_drive", "CtxWFProfilePath": "profile_path"}
U32 = {"CtxShadow": "remote_control", "CtxMaxConnectionTime": "max_connection_ms", "CtxMaxDisconnectionTime": "max_disconnection_ms", "CtxMaxIdleTime": "max_idle_ms"}


def nul_text(raw, wide):
    t = raw.decode("utf-16le") if wide else raw.decode("latin-1")
    assert t.endswith("\x00"), "text value not NUL-terminated"
    return t[:-1]


def expect_of(octets_hex):
    b = B.octets_to_bytes(bytes.fromhex(octets_hex))
    p = B.parse(b)
    v = {"signature": p["sig"], "property_count": p["count"], "properties": [], "text": {}}
    props = {}
    for q in p["props"]:
        v["properties"].append({"name": q["name"], "hex_value_len": len(q["hex_ascii"])})
        props.setdefault(q["name"], q)             # first occurrence (Windows' readers do the same, see FINDINGS)
    v["gate_ok"] = "CtxCfgPresent" in props and B.u32_of(props["CtxCfgPresent"]) == 0xB00B1E55
    if "CtxCfgFlags1" in props:
        fl = B.u32_of(props["CtxCfgFlags1"]); v["flags_hex"] = "%08x" % fl
        v["bits"] = {k: bool(fl & m) for k, m in BITS.items()}
        v["logon_allowed"] = not bool(fl & BITS["logon_disabled"])
    for n, k in U32.items():
        if n in props: v[k] = B.u32_of(props[n])
    for n, k in TEXT.items():
        a, w = props.get(n), props.get(n + "W")
        e = {}
        if a: e["ansi"] = nul_text(a["value"], False)
        if w: e["wide"] = nul_text(w["value"], True)
        if e: v["text"][k] = e
    return v


def check(rec_id, ex, r):
    w, a = r["wts"], r["adsi"]
    errs = []
    if r["octets"] == "(absent)": return errs
    if not ex["gate_ok"] or "flags_hex" not in ex: return errs          # Windows ignores the blob; checked via windows_effective
    if (w["AllowLogon"] == "1") != ex["logon_allowed"]: errs.append("AllowLogon")
    for k, wk in (("remote_control", "Shadowing"), ("max_connection_ms", "MaxConnection"), ("max_disconnection_ms", "MaxDisconnection"), ("max_idle_ms", "MaxIdle")):
        if k in ex and (int(w[wk]) & 0xFFFFFFFF) != ex[k]: errs.append(k)
    for k, wk in (("initial_program", "InitialProgram"), ("work_directory", "WorkDirectory"), ("home_dir", "HomeDir"), ("home_drive", "HomeDirDrive"), ("profile_path", "ProfilePath")):
        t = ex["text"].get(k)
        if t and "ansi" in t and w[wk] != t["ansi"] and t["ansi"].isascii(): errs.append(k)
        if t and "ansi" in t and "wide" in t and t["wide"].isascii() and t["wide"] != t["ansi"]: errs.append(k + " ansi/wide differ")
    return errs


def effective(ex, r):
    """Did Windows' own readers honour the blob? Compare what they returned with a value the blob carries that differs from their default."""
    if not ex["gate_ok"] or "flags_hex" not in ex: return "ignored" if r["wts"]["Shadowing"] == "1" and not any(k in ex for k in U32) else "ignored-or-no-fields"
    marks = [("remote_control", "Shadowing"), ("max_idle_ms", "MaxIdle"), ("max_connection_ms", "MaxConnection")]
    seen = [(int(r["wts"][wk]) & 0xFFFFFFFF) == ex[k] for k, wk in marks if k in ex and ex[k] != {"remote_control": 1}.get(k, 0)]
    texts = [r["wts"][wk] == ex["text"][k].get("ansi") for k, wk in (("home_dir", "HomeDir"), ("profile_path", "ProfilePath")) if k in ex["text"] and "ansi" in ex["text"][k]]
    allm = seen + texts
    if not allm: return "honoured (gate and flags read; no distinguishing value)"
    return "honoured" if all(allm) else "ignored"


def derive(d):
    cap = json.load(open(os.path.join(d, "captures.json")))
    os_name = cap["notes"]["OS"][0]
    recs, probes, bad = [], [], []
    for c in cap["cases"]:
        r = cap["recs"][c["id"]]
        if r["octets"] == "(absent)": bad.append(c["id"] + " absent"); continue
        ex = expect_of(r["octets"])
        errs = check(c["id"], ex, r)
        must_match = c["id"].startswith("TSP-W") and c["id"] != "TSP-W18"      # W18 and the probes intentionally include blobs Windows ignores
        if errs and must_match: bad.append("%s: %s" % (c["id"], errs))
        rec = {"id": c["id"], "primitive": "attr.tsprops", "call": "Decode", "args": {"value": {"hex": r["octets"]}},
               "hostile": False, "verified": "windows", "os": os_name, "dc": "dc1", "writer": {"adsi": "ADSI IADsTSUserEx (the API ADUC uses)", "raw": "plain LDAP modify (non-ADUC)", "probe": "plain LDAP modify (non-ADUC)"}[c["kind"]],
               "description": c["desc"], "windows_effective": effective(ex, r) if c["id"].startswith("TSP-W") else None, "readback_matches_blob": not errs,
               "expect": {"value": ex}, "windows_readback": {"wts": r["wts"], "adsi": r["adsi"]},
               "source": "T-1890 capture on %s; see FINDINGS.md" % os_name}
        (recs if c["id"].startswith("TSP-W") else probes).append(rec)
    if bad: sys.exit("derive: expectation does not match Windows' own readback: " + "; ".join(bad))
    with open(os.path.join(d, "records.jsonl"), "w") as f:
        for x in recs: f.write(json.dumps(x, sort_keys=True, ensure_ascii=True) + "\n")
    with open(os.path.join(d, "probes.jsonl"), "w") as f:
        for x in probes: f.write(json.dumps(x, sort_keys=True, ensure_ascii=True) + "\n")
    print("records %d, probes %d, all expectations match Windows readback" % (len(recs), len(probes)))
