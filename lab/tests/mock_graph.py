"""A tiny in-memory stand-in for the slice of Microsoft Graph + Entra sign-in that the Entra lab
scripts use (T-0183). Test infrastructure only: it lets `entra-lab-bootstrap` and `entra-lab-verify`
be proven offline, including idempotency, a recreated tenant and the failure paths."""
import base64, hashlib, json, re, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GRAPH_APP = "00000003-0000-0000-c000-000000000000"
ROLES = ["Organization.Read.All", "LicenseAssignment.Read.All", "LicenseAssignment.ReadWrite.All", "User.Create",
         "User.ReadUpdate.All", "User-PasswordProfile.ReadWrite.All", "User.EnableDisableAccount.All",
         "User.Read.All", "User.DeleteRestore.All", "User.RevokeSessions.All", "User.Invite.All",
         "Group.Create", "Group.ReadWrite.All", "GroupMember.ReadWrite.All", "GroupMember.Read.All",
         "AuditLog.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory",
         "User.ReadWrite.All", "Directory.ReadWrite.All"]  # the last two exist in Graph but must never be consented


def b64u(d): return base64.urlsafe_b64encode(d).rstrip(b"=")


class Tenant:
    def __init__(self, domain="labtest.onmicrosoft.com", pending_polls=1):
        self.id = str(uuid.uuid4()); self.domain = domain; self.pending = pending_polls
        self.log = []  # (method, path) of every write, to prove idempotency
        gsp = {"id": str(uuid.uuid4()), "appId": GRAPH_APP, "displayName": "Microsoft Graph",
               "appRoles": [{"id": str(uuid.uuid4()), "value": r, "allowedMemberTypes": ["Application"]} for r in ROLES]}
        self.c = {"applications": [], "servicePrincipals": [gsp], "users": [], "groups": [],
                  "roleAssignments": [], "roleEligibilitySchedules": []}
        self.assign = []  # appRoleAssignments
        self.roledefs = [{"id": str(uuid.uuid4()), "displayName": "Helpdesk Administrator"}]
        self.members = {}

    def role_by_value(self, v):
        return next(r for r in self.c["servicePrincipals"][0]["appRoles"] if r["value"] == v)


class Server:
    def __init__(self, tenant):
        self.t = tenant; self.tokens = {}; self.rejected_assertions = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _send(self, code, obj=None):
                b = json.dumps(obj if obj is not None else {}).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            def _body(self):
                n = int(self.headers.get("Content-Length") or 0); return self.rfile.read(n) if n else b""
            def do_GET(self): outer.handle(self, "GET")
            def do_POST(self): outer.handle(self, "POST")
            def do_PATCH(self): outer.handle(self, "PATCH")
            def do_DELETE(self): outer.handle(self, "DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def login(self): return f"http://127.0.0.1:{self.port}/login"
    @property
    def graph(self): return f"http://127.0.0.1:{self.port}/v1.0"
    def stop(self): self.httpd.shutdown(); self.httpd.server_close()

    # ---- sign-in -------------------------------------------------------------------------------
    def token_endpoint(self, h, form):
        t = self.t
        if form.get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
            if t.pending > 0:
                t.pending -= 1; return h._send(400, {"error": "authorization_pending"})
            tok = "admin-" + uuid.uuid4().hex; self.tokens[tok] = ("admin", None)
            return h._send(200, {"access_token": tok})
        if form.get("grant_type") == "client_credentials":
            app = next((a for a in t.c["applications"] if a["appId"] == form.get("client_id")), None)
            parts = form.get("client_assertion", "").split(".")
            if not app or len(parts) != 3 or form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                self.rejected_assertions += 1; return h._send(401, {"error": "invalid_client"})
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            thumbs = [k["customKeyIdentifier"].lower() for k in app.get("keyCredentials", [])]
            x5t = base64.urlsafe_b64decode(hdr.get("x5t", "") + "=" * (-len(hdr.get("x5t", "")) % 4)).hex()
            if x5t not in thumbs:
                self.rejected_assertions += 1
                return h._send(401, {"error": "invalid_client", "error_description": "certificate not registered"})
            sp = next(s for s in t.c["servicePrincipals"] if s["appId"] == app["appId"])
            ids = {a["appRoleId"] for a in t.assign if a["principalId"] == sp["id"]}
            roles = [r["value"] for r in t.c["servicePrincipals"][0]["appRoles"] if r["id"] in ids]
            payload = b64u(json.dumps({"roles": roles, "tid": t.id}).encode()).decode()
            tok = "x." + payload + ".y"; self.tokens[tok] = ("app", sp["id"])
            return h._send(200, {"access_token": tok})
        h._send(400, {"error": "unsupported_grant_type"})

    # ---- Graph ---------------------------------------------------------------------------------
    def handle(self, h, method):
        u = urlparse(h.path); q = parse_qs(u.query); path = u.path; body = h._body()
        if path.endswith("/devicecode"):
            return h._send(200, {"device_code": "dc", "message": "To sign in, open https://example.invalid/devicelogin and enter code TEST1234",
                                 "interval": 0, "expires_in": 60})
        if path.endswith("/oauth2/v2.0/token"):
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}; return self.token_endpoint(h, form)
        auth = h.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return h._send(401, {"error": {"code": "InvalidAuthenticationToken", "message": "bad token"}})
        kind, who = self.tokens[auth[7:]]
        path = path[len("/v1.0"):]
        t = self.t; data = json.loads(body) if body else {}
        if method != "GET": t.log.append((method, path))
        if path == "/organization":
            return h._send(200, {"value": [{"id": t.id, "verifiedDomains": [{"name": t.domain, "isInitial": True}]}]})
        m = re.fullmatch(r"/(applications|servicePrincipals|users|groups)", path)
        if m:
            col = t.c[m.group(1)]
            if method == "GET":
                return h._send(200, {"value": [x for x in col if self.match(x, q.get("$filter", [""])[0])]})
            obj = dict(data); obj["id"] = str(uuid.uuid4())
            if m.group(1) == "applications": obj.setdefault("appId", str(uuid.uuid4())); obj.setdefault("keyCredentials", []); obj.setdefault("passwordCredentials", [])
            col.append(obj); return h._send(201, obj)
        m = re.fullmatch(r"/(applications|users)/([^/]+)", path)
        if m:
            obj = next((x for x in t.c[m.group(1)] if x["id"] == m.group(2)), None)
            if not obj: return h._send(404, {"error": {"code": "Request_ResourceNotFound", "message": "nf"}})
            if method == "PATCH":
                if "keyCredentials" in data:
                    for k in data["keyCredentials"]:
                        k["customKeyIdentifier"] = hashlib.sha1(base64.b64decode(k["key"])).hexdigest().upper(); k.pop("key")
                obj.update(data); return h._send(204)
            return h._send(200, obj)
        m = re.fullmatch(r"/applications/([^/]+)/owners(/.*)?", path)
        if m: return h._send(200, {"value": []})
        m = re.fullmatch(r"/servicePrincipals/([^/]+)/appRoleAssignments(?:/([^/]+))?", path)
        if m:
            if method == "GET": return h._send(200, {"value": [a for a in t.assign if a["principalId"] == m.group(1)]})
            if method == "DELETE": t.assign[:] = [a for a in t.assign if a["id"] != m.group(2)]; return h._send(204)
            a = dict(data); a["id"] = str(uuid.uuid4()); t.assign.append(a); return h._send(201, a)
        m = re.fullmatch(r"/groups/([^/]+)/members(/\$ref)?", path)
        if m:
            mem = t.members.setdefault(m.group(1), [])
            if method == "GET": return h._send(200, {"value": [{"id": i} for i in mem]})
            mem.append(data["@odata.id"].rsplit("/", 1)[1]); return h._send(204)
        if path == "/roleManagement/directory/roleDefinitions":
            return h._send(200, {"value": [d for d in t.roledefs if self.match(d, q.get("$filter", [""])[0])]})
        if path in ("/roleManagement/directory/roleAssignments", "/roleManagement/directory/roleEligibilitySchedules",
                    "/roleManagement/directory/roleEligibilityScheduleRequests"):
            col = t.c["roleEligibilitySchedules" if "Eligibility" in path else "roleAssignments"]
            if method == "GET": return h._send(200, {"value": [x for x in col if self.match(x, q.get("$filter", [""])[0])]})
            obj = dict(data); obj["id"] = str(uuid.uuid4()); col.append(obj); return h._send(201, obj)
        h._send(404, {"error": {"code": "NotImplementedInMock", "message": path}})

    @staticmethod
    def match(obj, flt):
        for part in [p for p in re.split(r"\s+and\s+", flt) if p]:
            k, v = re.fullmatch(r"(\w+) eq '(.*)'", part.strip()).groups()
            if obj.get(k) != v: return False
        return True
