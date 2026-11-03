"""The fake Proxmox host CLI (pveum, pvesh, pveversion) over one JSON state file. Light imports on purpose."""
import json, re, sys, uuid
from pathlib import Path

def load(path): return json.loads(Path(path).read_text())
def save(path, st): Path(path).write_text(json.dumps(st))


def _opts(args):
    out, i = {}, 0
    while i < len(args):
        if not args[i].startswith("--"):
            raise SystemExit(f"fake pve: unexpected argument {args[i]!r}")
        out[args[i][2:]] = args[i + 1]; i += 2
    return out


def fake_pve(tool, argv, statef):
    st = load(statef)
    st["log"].append([tool, *argv])
    try:
        rc = _fake(tool, argv, st)
    finally:
        save(statef, st)
    return rc


def _fake(tool, a, st):
    def out(x): print(json.dumps(x))
    if tool == "pveversion":
        print(st["version"]); return 0
    if tool == "pvesh":
        assert a[0] == "get" and a[-2:] == ["--output-format", "json"], a
        path, o = a[1], _opts(a[2:-2])
        if path == "/cluster/resources": out(st["vms"])
        elif m := re.fullmatch(r"/nodes/[^/]+/qemu/(\d+)/config", path): out(st["config"][m.group(1)])
        elif path == "/storage": out(st["storage"])
        elif re.fullmatch(r"/nodes/[^/]+/certificates/info", path): out(st["certs"])
        elif path == "/pools": out([{"poolid": p} for p in st["pools"]])
        elif path == "/access/roles": out([{"roleid": r, "privs": " ".join(v)} for r, v in st["roles"].items()])
        elif path == "/access/users": out([{"userid": u} for u in st["users"]])
        elif m := re.fullmatch(r"/access/users/([^/]+)/token", path): out([{"tokenid": t.split("!")[1]} for t in st["tokens"] if t.startswith(m.group(1) + "!")])
        elif path == "/access/acl": out([e for e in st["acl"] if not e.get("hidden")])  # hidden: an ACL the script cannot see
        else: print("fake pvesh: no such path", path, file=sys.stderr); return 1
        return 0
    assert tool == "pveum"
    if a[:2] == ["pool", "add"]:
        o = _opts(a[3:]); st["pools"][a[2]] = {"members": []}
    elif a[:2] == ["pool", "modify"]:
        o = _opts(a[3:])
        if a[2] not in st["pools"]: print("pool does not exist", file=sys.stderr); return 2
        for v in o["vms"].split(","):
            if int(v) not in st["pools"][a[2]]["members"]: st["pools"][a[2]]["members"].append(int(v))
    elif a[:2] in (["role", "add"], ["role", "modify"]):
        o = _opts(a[3:]); exists = a[2] in st["roles"]
        if (a[1] == "add") == exists: print("role exists/missing", file=sys.stderr); return 2
        st["roles"][a[2]] = o["privs"].split()
    elif a[:2] == ["role", "delete"]:
        st["roles"].pop(a[2], None); st["acl"] = [e for e in st["acl"] if e["roleid"] != a[2]]
    elif a[:2] == ["user", "add"]:
        if a[2] in st["users"]: print("user exists", file=sys.stderr); return 2
        st["users"][a[2]] = {}
    elif a[:2] == ["user", "delete"]:
        st["users"].pop(a[2], None)
        st["tokens"] = {t: v for t, v in st["tokens"].items() if not t.startswith(a[2] + "!")}
        st["acl"] = [e for e in st["acl"] if not e["ugid"].startswith(a[2])]
    elif a[:3] == ["user", "token", "add"]:
        o = _opts(a[5:]); tid = f"{a[3]}!{a[4]}"
        if tid in st["tokens"]: print("token exists", file=sys.stderr); return 2
        secret = str(uuid.uuid4()); st["tokens"][tid] = {"privsep": o["privsep"], "secret": secret}
        out({"full-tokenid": tid, "info": {"privsep": o["privsep"]}, "value": secret})
        st["log"][-1] = ["pveum", "user", "token", "add", a[3], a[4], "…"]  # the log never keeps the secret
        return 0
    elif a[:3] == ["user", "token", "remove"]:
        tid = f"{a[3]}!{a[4]}"
        if tid not in st["tokens"]: print("no such token", file=sys.stderr); return 2
        del st["tokens"][tid]; st["acl"] = [e for e in st["acl"] if e["ugid"] != tid]
    elif a[:2] == ["acl", "modify"]:
        o = _opts(a[3:]); path = a[2]
        for ug, typ in [(o["users"], "user"), (o["tokens"], "token")]:
            if o["roles"] not in st["roles"]: print("no such role", file=sys.stderr); return 2
            e = {"path": path, "roleid": o["roles"], "type": typ, "ugid": ug, "propagate": int(o["propagate"])}
            if e not in st["acl"]: st["acl"].append(e)
    elif a[:2] == ["acl", "delete"]:
        o = _opts(a[3:]); ug = o.get("users") or o.get("tokens")
        st["acl"] = [e for e in st["acl"] if not (e["path"] == a[2] and e["roleid"] == o["roles"] and e["ugid"] == ug)]
    else:
        print("fake pveum: unsupported", a, file=sys.stderr); return 2
    return 0


