"""Test doubles for the Proxmox lab tooling (T-1326): a fake Proxmox host (pveum/pvesh/pveversion behind a
fake ssh, one JSON state file) and a stub HTTPS API that derives the token's permissions from the same state.
Nothing here talks to a real Proxmox."""
import hashlib, http.server, json, os, re, ssl, subprocess, sys, threading, uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
import pvelab as P

NODE = "pve1"


def initial_state(fingerprint):
    return {"version": "pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.4-2-pve)",
            "vms": [{"vmid": 119, "node": NODE, "type": "qemu", "name": "dc1", "status": "running"},
                    {"vmid": 200, "node": NODE, "type": "qemu", "name": "production-db", "status": "running"},
                    {"vmid": 201, "node": NODE, "type": "qemu", "name": "other", "status": "stopped"}],
            "config": {"119": {"scsi0": "local-lvm:vm-119-disk-0,size=60G", "ide2": "local:iso/x.iso,media=cdrom",
                               "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"}},
            "storage": [{"storage": "local-lvm", "content": "rootdir,images"}, {"storage": "local", "content": "iso,vztmpl,backup"}],
            "certs": [{"filename": "pve-ssl.pem", "fingerprint": ":".join(fingerprint[i:i + 2].upper() for i in range(0, 64, 2))}],
            "pools": {}, "roles": {"Administrator": ["Sys.Audit", "Sys.Modify", "Permissions.Modify"]}, "users": {"root@pam": {}},
            "tokens": {}, "acl": [{"path": "/", "roleid": "Administrator", "type": "user", "ugid": "root@pam", "propagate": 1}],
            "log": [], "snapshots": {}}


from fakepve import fake_pve, load, save  # noqa: E402  (kept in its own light module: it starts once per remote command)


def install_fakes(bindir, statef, logf):
    """bindir/ssh plus bindir/pve/{pveum,pvesh,pveversion}; the ssh logs every remote command it is asked to run."""
    bindir = Path(bindir); (bindir / "pve").mkdir(parents=True, exist_ok=True)
    for t in ("pveum", "pvesh", "pveversion"):
        f = bindir / "pve" / t
        f.write_text(f"#!{sys.executable} -S\nimport sys\nsys.path.insert(0, {str(HERE)!r})\nimport fakepve\n"
                     f"sys.exit(fakepve.fake_pve({t!r}, sys.argv[1:], {str(statef)!r}))\n"); f.chmod(0o755)
    ssh = bindir / "ssh"
    ssh.write_text(f"""#!{sys.executable} -S
import os, subprocess, sys
a = sys.argv[1:]
if '-O' in a: sys.exit(0)                      # connection-sharing control command
i = a.index('--'); host, remote = a[i + 1], ' '.join(a[i + 2:])
opts = a[:i]
open({str(logf)!r}, 'a').write(repr((host, opts, remote)) + '\\n')
import shlex                                  # in-process: spawning sh + python per command made the suite slow
argv = shlex.split(remote)                     # (test_every_remote_command_is_one_shell_safe_argv checks the round-trip)
sys.path.insert(0, {str(HERE)!r})
import fakepve
if argv[0] not in ('pveum', 'pvesh', 'pveversion'): sys.exit(127)
sys.exit(fakepve.fake_pve(argv[0], argv[1:], {str(statef)!r}))
""")
    ssh.chmod(0o755)
    return ssh


# ---- the stub HTTPS API ---------------------------------------------------------------------------
def effective(st, tokid):
    perms = {}
    for e in st["acl"]:
        if e["ugid"] != tokid:
            continue
        privs = set(st["roles"].get(e["roleid"], []))
        paths = [e["path"]]
        if e["path"].startswith("/pool/"):
            paths += [f"/vms/{v}" for v in st["pools"].get(e["path"][6:], {}).get("members", [])]
        elif e["path"] in ("/", "/vms"):
            paths += [f"/vms/{v['vmid']}" for v in st["vms"]]
        for p in paths:
            perms.setdefault(p, set()).update(privs)
    return perms


CONFIG_PRIV = ((r"cores|sockets|vcpus|cpu|cpulimit|cpuunits|numa", "VM.Config.CPU"), (r"memory|balloon|shares", "VM.Config.Memory"),
               (r"bios|machine|scsihw|vga|rng0|audio0", "VM.Config.HWType"),
               (r"name|ostype|agent|boot|onboot|description|tags|start", "VM.Config.Options"))


def path_of(params):
    return f"/pool/{params['pool']}" if "pool" in params else f"/vms/{params.get('vmid')}"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, data=None):
        body = json.dumps({"data": data}).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _do(self, method):
        srv = self.server.owner
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        u = urlparse(self.path)
        srv.requests.append({"method": method, "path": u.path, "query": u.query, "body": body,
                             "auth": self.headers.get("Authorization")})
        st = load(srv.statef)
        tokid = srv.tokid
        sec = st["tokens"].get(tokid, {}).get("secret")
        if self.headers.get("Authorization") != f"PVEAPIToken={tokid}={sec}":
            return self._send(401)
        if srv.fail_path and srv.fail_path in u.path:
            return self._send(500)
        p = u.path.removeprefix("/api2/json"); eff = effective(st, tokid)
        pool_of = {v: q for q, pl in st["pools"].items() for v in pl["members"]}
        visible = [v for v in st["vms"] if "VM.Audit" in eff.get(f"/vms/{v['vmid']}", ())]
        params = {k: x[0] for k, x in parse_qs(body if method != "GET" else u.query).items()}

        def allow(path, *privs):
            """The real Proxmox rule, per endpoint (see the apidoc.js table): every privilege must be held at the path."""
            return all(priv in eff.get(path, ()) for priv in privs)

        def deny(path, *privs):
            return self._send(403, f"Permission check failed ({path}, {'|'.join(privs)})")

        if method == "GET" and p == "/access/permissions":
            return self._send(200, {k: {x: 1 for x in sorted(v)} for k, v in eff.items()})
        if method == "GET" and p == "/cluster/resources":   # filtered by VM.Audit; the real host sends no `pool` field (T-1327)
            return self._send(200, [dict(v, id=f"qemu/{v['vmid']}") for v in visible])
        if method == "GET" and p == "/pools":
            # real host (T-1327): without poolid a pool is listed only with Pool.Audit; with poolid=X the members the
            # token holds VM.Audit on are returned
            if "poolid" in params:
                q = params["poolid"]; pl = st["pools"].get(q)
                if pl is None or not (allow(f"/pool/{q}", "Pool.Audit") or visible): return self._send(200, [])
                return self._send(200, [{"poolid": q, "members": [dict(v, id=f"qemu/{v['vmid']}") for v in visible
                                                                    if v["vmid"] in pl["members"]]}])
            return self._send(200, [{"poolid": q} for q in st["pools"] if allow(f"/pool/{q}", "Pool.Audit")])
        if method == "GET" and (m := re.fullmatch(r"/pools/([\w-]+)", p)):
            if not allow(f"/pool/{m.group(1)}", "Pool.Audit"): return deny(f"/pool/{m.group(1)}", "Pool.Audit")
            pool = st["pools"].get(m.group(1)) or {"members": []}
            return self._send(200, {"members": [dict(v, id=f"qemu/{v['vmid']}") for v in st["vms"] if v["vmid"] in pool["members"]]})
        if method == "GET" and p == "/cluster/nextid":
            return self._send(200, "301")
        if method == "GET" and re.fullmatch(r"/nodes/[\w-]+/tasks/.+/status", p):   # the task's owner may always read it
            return self._send(200, {"status": "stopped", "exitstatus": srv.task_exit})
        if method == "GET" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/snapshot", p)):
            if not allow(f"/vms/{m.group(1)}", "VM.Audit"): return deny(f"/vms/{m.group(1)}", "VM.Audit")
            return self._send(200, [{"name": s} for s in st["snapshots"].get(m.group(1), [])] + [{"name": "current"}])
        task = f"UPID:{NODE}:000A1B2C:0123ABCD:65F00000:qmtask:1:{tokid}:"
        if method == "POST" and re.fullmatch(r"/nodes/[\w-]+/qemu", p):
            # create: VM.Allocate on the pool, Datastore.AllocateSpace per disk store, SDN.Use per bridge, VM.Config.* per key
            need = [(f"/pool/{params['pool']}" if "pool" in params else f"/vms/{params.get('vmid')}", "VM.Allocate")]
            for k, x in params.items():
                if re.fullmatch(r"(scsi|efidisk|tpmstate)\d*", k) and not x.startswith("none"):
                    need += [(f"/storage/{x.split(':')[0]}", "Datastore.AllocateSpace"), (path_of(params), "VM.Config.Disk")]
                if k.startswith("net"):
                    need += [(f"/sdn/zones/localnetwork/{re.search('bridge=([^,]+)', x).group(1)}", "SDN.Use"),
                             (path_of(params), "VM.Config.Network")]
                if k == "ide2":
                    need += [(path_of(params), "VM.Config.CDROM"), (f"/storage/{x.split(':')[0]}", "Datastore.Audit")]
                for pat, priv in CONFIG_PRIV:
                    if re.fullmatch(pat, k): need.append((path_of(params), priv))
            for path, priv in need:
                if not allow(path, priv): return deny(path, priv)
            return self._send(200, task)
        if method == "POST" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/status/(start|stop|shutdown)", p)):
            if not allow(f"/vms/{m.group(1)}", "VM.PowerMgmt"): return deny(f"/vms/{m.group(1)}", "VM.PowerMgmt")
            return self._send(200, task)
        if method == "POST" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/snapshot", p)):
            if not allow(f"/vms/{m.group(1)}", "VM.Snapshot"): return deny(f"/vms/{m.group(1)}", "VM.Snapshot")
            return self._send(200, task)
        if method == "POST" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/snapshot/[\w.-]+/rollback", p)):
            if not allow(f"/vms/{m.group(1)}", "VM.Snapshot.Rollback"): return deny(f"/vms/{m.group(1)}", "VM.Snapshot.Rollback")
            return self._send(200, task)
        if method == "PUT" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/config", p)):
            vm = f"/vms/{m.group(1)}"
            need = [(vm, "VM.Config.CDROM")] if "ide2" in params else []
            if "ide2" in params and not params["ide2"].startswith("none"):
                need.append((f"/storage/{params['ide2'].split(':')[0]}", "Datastore.Audit"))
            for path, priv in need:
                if not allow(path, priv): return deny(path, priv)
            return self._send(200, None)
        return self._send(404)

    def do_GET(self): self._do("GET")
    def do_POST(self): self._do("POST")
    def do_PUT(self): self._do("PUT")
    def do_DELETE(self): self._do("DELETE")


class StubApi:
    def __init__(self, statef, certfile, keyfile, tokid=P.TOKEN_ID):
        self.statef, self.tokid, self.requests, self.fail_path, self.task_exit = statef, tokid, [], None, "OK"
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.owner = self
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(certfile, keyfile)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True); self.thread.start()

    def stop(self): self.httpd.shutdown(); self.httpd.server_close()


def make_cert(d, name="c"):
    d = Path(d); k, c = d / f"{name}.key", d / f"{name}.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=pve.test",
                    "-keyout", str(k), "-out", str(c)], check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", str(c), "-outform", "DER"], check=True, capture_output=True).stdout
    return str(c), str(k), hashlib.sha256(der).hexdigest()


def bootstrapped_state(fingerprint, extra_acl=(), leak=False):
    """The state a correct bootstrap leaves behind, built directly (for driver tests)."""
    st = initial_state(fingerprint)
    secret = str(uuid.uuid4())
    st["pools"][P.POOL] = {"members": [119]}
    st["roles"][P.ROLE] = list(P.WORKER_PRIVS)
    st["users"][P.USER] = {}
    st["tokens"][P.TOKEN_ID] = {"privsep": "1", "secret": secret}
    for path in (f"/pool/{P.POOL}", "/storage/local-lvm", "/sdn/zones/localnetwork/vmbr0"):
        for typ, ug in (("user", P.USER), ("token", P.TOKEN_ID)):
            st["acl"].append({"path": path, "roleid": P.ROLE, "type": typ, "ugid": ug, "propagate": 1})
    for e in extra_acl:
        st["acl"].append(dict(e, type="token", ugid=P.TOKEN_ID, propagate=1))
    return st, secret


def write_env(path, host, port, secret, fingerprint, **over):
    v = {"PVE_HOST": host, "PVE_PORT": str(port), "PVE_NODE": NODE, "PVE_TOKEN_ID": P.TOKEN_ID, "PVE_TOKEN_SECRET": secret,
         "PVE_CERT_SHA256": fingerprint, "PVE_POOL": P.POOL, "PVE_STORAGE": "local-lvm", "PVE_ISO_STORAGE": "local-lvm",
         "PVE_BRIDGE": "vmbr0"}
    v.update(over)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("".join(f"{k}={x}\n" for k, x in v.items()))
    os.chmod(path, 0o600)
