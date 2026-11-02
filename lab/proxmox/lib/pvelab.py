"""Shared pieces of the Proxmox lab pool tooling (T-1326, D-0022). Python stdlib only.

Used by lab/proxmox/bin/proxmox-lab (worker driver) and proxmox-lab-bootstrap (the CEO's one-time
command and its revoke). Rules this file enforces for both:
  * every Proxmox API call is a typed (method, path, params) triple; paths are built from validated
    parts, never by formatting free text into a URL; remote shell commands are argv lists joined with
    shlex.join, and every value is validated against a strict pattern first (CLAUDE.md rule 5);
  * the API's TLS certificate is pinned by SHA-256 fingerprint and checked after the handshake and
    BEFORE any HTTP byte (and so before the token) is sent; there is no "insecure" mode;
  * the token secret lives only in the 0600 env file; nothing here prints it.
"""
import hashlib, http.client, json, os, re, shlex, socket, ssl, stat, subprocess, urllib.parse

POOL = "adiq-lab"
USER = "adiq-lab@pve"
TOKEN_NAME = "worker"
TOKEN_ID = f"{USER}!{TOKEN_NAME}"
ROLE = "AdiqLabWorker"
ISO_ROLE = "AdiqLabIso"
DC1_VMID = 119
ENV_NAME = ".proxmox-lab.env"

# The complete privilege set of the worker role (acceptance 1). verify-scope fails closed on anything
# outside it. Deliberately absent: Sys.*, Permissions.*, User.*, Pool.* (membership is read from
# /cluster/resources, which needs VM.Audit; GET /pools needs Pool.Audit), Realm.*, Group.*,
# Datastore.Allocate / AllocateTemplate, VM.Monitor, VM.Migrate, VM.Clone, VM.Backup, SDN.Allocate.
WORKER_PRIVS = (
    "VM.Allocate", "VM.Audit", "VM.Console", "VM.PowerMgmt",
    "VM.Snapshot", "VM.Snapshot.Rollback",
    "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Disk", "VM.Config.HWType",
    "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options",
    "Datastore.AllocateSpace", "Datastore.Audit",
    "SDN.Use",
)
ISO_PRIVS = ("Datastore.Audit",)  # a separate ISO store is read-only for the token
ALL_ALLOWED_PRIVS = frozenset(WORKER_PRIVS) | frozenset(ISO_PRIVS)
FORBIDDEN_PREFIXES = ("Sys.", "Permissions.", "User.", "Realm.", "Group.", "Pool.")

HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[?[0-9A-Fa-f:]{2,39}\]?)$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")          # node, storage, bridge, snapshot
FPR_RE = re.compile(r"^[0-9a-f]{64}$")
VOLID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}:iso/[A-Za-z0-9][A-Za-z0-9_. +()-]{0,120}\.iso$")
UPID_RE = re.compile(r"^UPID:[A-Za-z0-9._-]+:[0-9A-F:]+:[A-Za-z0-9._:@!-]*:$")


class LabError(Exception):
    """A refusal or failure the user must see; exit status 2 (1 for verify-scope failures)."""


def vmid_of(text):
    if not re.fullmatch(r"[1-9][0-9]{2,8}", str(text)):
        raise LabError(f"invalid VMID {text!r} (3-9 digits)")
    return int(text)


def check(rx, value, what):
    if not isinstance(value, str) or not rx.fullmatch(value):
        raise LabError(f"invalid {what}: {str(value)[:60]!r}")
    return value


def norm_fpr(text):
    f = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    if not FPR_RE.fullmatch(f):
        raise LabError("certificate fingerprint must be a SHA-256 (64 hex digits)")
    return f


# ---- env file -------------------------------------------------------------------------------------
def repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def env_candidates():
    """PROXMOX_LAB_ENV, then this checkout, then the main checkout (a worktree has no gitignored files)."""
    out = []
    if os.environ.get("PROXMOX_LAB_ENV"):
        out.append(os.environ["PROXMOX_LAB_ENV"])
    root = repo_root()
    out.append(os.path.join(root, "lab", ENV_NAME))
    try:
        common = subprocess.run(["git", "-C", root, "rev-parse", "--path-format=absolute", "--git-common-dir"],
                                capture_output=True, text=True, timeout=10).stdout.strip()
        if common:
            out.append(os.path.join(os.path.dirname(common), "lab", ENV_NAME))
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def find_env():
    for p in env_candidates():
        if os.path.isfile(p):
            return p
    raise LabError("no lab/.proxmox-lab.env found (the CEO's one-time `make proxmox-lab-bootstrap` writes it; "
                   "set PROXMOX_LAB_ENV to point at the main checkout's file). Tried: " + ", ".join(env_candidates()))


def load_env(path=None):
    path = path or find_env()
    st = os.stat(path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise LabError(f"{path} is mode {stat.S_IMODE(st.st_mode):04o}; it holds the token secret and must be 0600")
    if st.st_uid != os.getuid():
        raise LabError(f"{path} is not owned by the current user")
    env = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    for k in ("PVE_HOST", "PVE_PORT", "PVE_NODE", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PVE_CERT_SHA256",
              "PVE_POOL", "PVE_STORAGE", "PVE_BRIDGE"):
        if not env.get(k):
            raise LabError(f"{path} lacks {k}; re-run the bootstrap")
    check(HOST_RE, env["PVE_HOST"], "PVE_HOST")
    if not re.fullmatch(r"[0-9]{1,5}", env["PVE_PORT"]):
        raise LabError("invalid PVE_PORT")
    env["PVE_CERT_SHA256"] = norm_fpr(env["PVE_CERT_SHA256"])
    for k in ("PVE_NODE", "PVE_STORAGE", "PVE_BRIDGE", "PVE_POOL"):
        check(NAME_RE, env[k], k)
    if env["PVE_POOL"] != POOL:
        raise LabError(f"PVE_POOL must be {POOL}")
    check(re.compile(r"^[A-Za-z0-9._@-]+![A-Za-z0-9_-]+$"), env["PVE_TOKEN_ID"], "PVE_TOKEN_ID")
    check(re.compile(r"^[0-9a-fA-F-]{20,64}$"), env["PVE_TOKEN_SECRET"], "PVE_TOKEN_SECRET")  # shape only; never echoed
    env.setdefault("PVE_ISO_STORAGE", env["PVE_STORAGE"])
    return env


# ---- pinned-TLS API client ------------------------------------------------------------------------
class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Handshake, then compare the server certificate's SHA-256 with the pin before any request is sent.
    Chain validation is replaced by the pin (Proxmox certs are self-signed or from a private CA); the pin
    is stronger than a CA check for one known host. A mismatch closes the socket: no token leaves."""

    def __init__(self, host, port, fingerprint, timeout=30):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False           # identity is the pinned certificate, not a name
        ctx.verify_mode = ssl.CERT_NONE      # replaced by the fingerprint comparison in connect()
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._pin = fingerprint

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        got = hashlib.sha256(der).hexdigest() if der else ""
        if got != self._pin:
            self.sock.close()
            raise LabError(f"TLS fingerprint mismatch for {self.host}:{self.port}: pinned {self._pin[:16]}…, "
                           f"server presented {got[:16]}…; refusing to send anything (re-run the bootstrap only "
                           f"if the Proxmox certificate was legitimately replaced)")


class Api:
    def __init__(self, env):
        self.env = env
        self.host, self.port = env["PVE_HOST"].strip("[]"), int(env["PVE_PORT"])
        self.auth = f"PVEAPIToken={env['PVE_TOKEN_ID']}={env['PVE_TOKEN_SECRET']}"
        self.pin = env["PVE_CERT_SHA256"]

    def call(self, method, path, params=None):
        """method: GET|POST|PUT|DELETE. path: '/pools/adiq-lab' (validated by the caller's helpers).
        params: dict of typed values, sent form-encoded (or as the query string for GET)."""
        if method not in ("GET", "POST", "PUT", "DELETE") or not re.fullmatch(r"/[A-Za-z0-9_./:@!-]*", path) or ".." in path:
            raise LabError(f"refusing malformed API request {method} {path!r}")
        body, url = None, "/api2/json" + path
        enc = urllib.parse.urlencode({k: ("1" if v is True else "0" if v is False else str(v))
                                      for k, v in (params or {}).items() if v is not None})
        headers = {"Authorization": self.auth, "Accept": "application/json"}
        if method == "GET":
            url += ("?" + enc) if enc else ""
        else:
            body = enc.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn = PinnedHTTPSConnection(self.host, self.port, self.pin)
        try:
            conn.request(method, url, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(8 * 1024 * 1024)
        except (OSError, http.client.HTTPException) as e:
            raise LabError(f"{method} {path}: {type(e).__name__}: {e}") from None
        finally:
            conn.close()
        if resp.status >= 300:
            msg = raw.decode("utf-8", "replace")[:300].replace(self.env["PVE_TOKEN_SECRET"], "***")
            raise LabError(f"{method} {path}: HTTP {resp.status} {resp.reason}: {msg}")
        try:
            return json.loads(raw)["data"]
        except (ValueError, KeyError, TypeError):
            raise LabError(f"{method} {path}: unexpected response shape") from None


# ---- remote commands for the bootstrap (argv lists -> one quoted string) --------------------------
def remote(*argv):
    if not argv or not all(isinstance(a, str) and "\x00" not in a and "\n" not in a for a in argv):
        raise LabError("bad remote argv")
    return shlex.join(argv)
