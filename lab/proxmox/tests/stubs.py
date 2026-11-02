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
env = dict(os.environ, PATH={str(bindir / 'pve')!r} + os.pathsep + os.environ['PATH'])
sys.exit(subprocess.run(['sh', '-c', remote], env=env).returncode)
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
        visible = [v for v in st["vms"] if "VM.Audit" in eff.get(f"/vms/{v['vmid']}", ())]
        if method == "GET" and p == "/access/permissions":
            return self._send(200, {k: {x: 1 for x in sorted(v)} for k, v in eff.items()})
        if method == "GET" and p == "/cluster/resources":
            return self._send(200, [dict(v, id=f"qemu/{v['vmid']}") for v in visible])
        if method == "GET" and p == "/pools":
            return self._send(200, [{"poolid": q} for q in st["pools"] if "VM.Audit" in eff.get(f"/pool/{q}", ())])
        if method == "GET" and (m := re.fullmatch(r"/pools/([\w-]+)", p)):
            pool = st["pools"].get(m.group(1))
            if pool is None or f"/pool/{m.group(1)}" not in eff: return self._send(403)
            return self._send(200, {"members": [dict(v, id=f"qemu/{v['vmid']}") for v in st["vms"] if v["vmid"] in pool["members"]]})
        if method == "GET" and p == "/cluster/nextid":
            return self._send(200, "301")
        if method == "GET" and re.fullmatch(r"/nodes/[\w-]+/tasks/.+/status", p):
            return self._send(200, {"status": "stopped", "exitstatus": srv.task_exit})
        if method == "GET" and (m := re.fullmatch(r"/nodes/[\w-]+/qemu/(\d+)/snapshot", p)):
            return self._send(200, [{"name": s} for s in st["snapshots"].get(m.group(1), [])] + [{"name": "current"}])
        if method in ("POST", "PUT") and re.fullmatch(r"/nodes/[\w-]+/qemu(/\d+/(status/\w+|snapshot(/[\w.-]+/rollback)?))?", p):
            return self._send(200, f"UPID:{NODE}:000A1B2C:0123ABCD:65F00000:qmtask:1:{tokid}:")
        if method == "PUT" and re.fullmatch(r"/nodes/[\w-]+/qemu/\d+/config", p):
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
