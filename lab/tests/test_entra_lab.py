"""Offline proof of the Entra lab harness (T-0183): runs the real shell scripts against mock_graph.
Covers acceptance 1-3 and the failure paths that make `entra-lab-verify` a gate."""
import os, re, shutil, stat, subprocess, tempfile, unittest, hashlib
from pathlib import Path
import mock_graph as mg

LAB = Path(__file__).resolve().parent.parent
REPO = LAB.parent
BOOT, VERIFY = LAB / "bin/entra-lab-bootstrap", LAB / "bin/entra-lab-verify"


class EntraLab(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); self.tenant = mg.Tenant(); self.srv = mg.Server(self.tenant)

    def tearDown(self):
        self.srv.stop(); shutil.rmtree(self.d)

    def run_s(self, script, *args, srv=None):
        srv = srv or self.srv
        env = dict(os.environ, GRAPH_BASE=srv.graph, LOGIN_BASE=srv.login, ENTRA_ENV=str(self.d / "e.env"),
                   ENTRA_PEM=str(self.d / "e.pem"), ENTRA_RETRY_SLEEP="0")
        return subprocess.run([str(script), *args], env=env, capture_output=True, text=True, timeout=120)

    def boot(self, *a, srv=None):
        r = self.run_s(BOOT, "--yes", *a, srv=srv); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); return r

    def counts(self, t=None):
        t = t or self.tenant
        return {k: len(v) for k, v in t.c.items()} | {"assign": len(t.assign)}

    def test_bootstrap_then_verify_and_no_secret_output(self):  # acceptance 1 + 2
        r = self.boot()
        for f in ("e.env", "e.pem"):
            self.assertEqual(stat.S_IMODE((self.d / f).stat().st_mode), 0o600)
        out = r.stdout + r.stderr
        pem = (self.d / "e.pem").read_text()
        self.assertIn("PRIVATE KEY", pem)
        for secret in re.findall(r"[A-Za-z0-9+/=]{40,}", pem):
            self.assertNotIn(secret, out)
        self.assertIsNone(re.search(r"admin-[0-9a-f]{32}", out))  # bootstrap access token
        self.assertNotIn("PRIVATE KEY", out); self.assertNotIn("Lab-", out)  # no seeded passwords
        env = (self.d / "e.env").read_text()
        self.assertIn(f"ENTRA_TENANT_ID={self.tenant.id}", env)
        self.assertNotIn("SECRET", env.upper().replace("CLIENT_SECRET_NOT_USED", ""))
        app = self.tenant.c["applications"][0]
        self.assertEqual(app["passwordCredentials"], []); self.assertEqual(len(app["keyCredentials"]), 1)
        v = self.run_s(VERIFY); self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertIn("verify OK", v.stderr); self.assertNotIn("PRIVATE KEY", v.stdout + v.stderr)

    def test_consent_is_exactly_the_expected_set(self):
        self.boot()
        sp = [s for s in self.tenant.c["servicePrincipals"] if s["appId"] != mg.GRAPH_APP][0]
        got = {r["value"] for r in self.tenant.c["servicePrincipals"][0]["appRoles"]
               if r["id"] in {a["appRoleId"] for a in self.tenant.assign if a["principalId"] == sp["id"]}}
        want = {l for l in (LAB / "entra/permissions.txt").read_text().split("\n") if l and not l.startswith("#")}
        self.assertEqual(got, want)
        self.assertNotIn("User.ReadWrite.All", got); self.assertNotIn("Directory.ReadWrite.All", got)

    def test_rerun_is_idempotent(self):  # acceptance 3 (same tenant)
        self.boot(); before = self.counts(); pem = (self.d / "e.pem").read_bytes(); self.tenant.log.clear()
        r = self.boot()
        self.assertEqual(self.counts(), before)
        self.assertEqual((self.d / "e.pem").read_bytes(), pem)
        self.assertEqual([w for w in self.tenant.log if w[0] in ("POST",) ], [])
        self.assertIn("keeping the existing certificate", r.stderr)
        self.assertEqual(self.run_s(VERIFY).returncode, 0)

    def test_rerun_repairs_drift(self):
        self.boot()
        sp = [s for s in self.tenant.c["servicePrincipals"] if s["appId"] != mg.GRAPH_APP][0]
        extra = self.tenant.role_by_value("Directory.ReadWrite.All")
        self.tenant.assign.append({"id": "x", "principalId": sp["id"], "resourceId": self.tenant.c["servicePrincipals"][0]["id"], "appRoleId": extra["id"]})
        self.tenant.assign.pop(0)
        self.assertNotEqual(self.run_s(VERIFY).returncode, 0)
        self.boot(); self.assertEqual(self.run_s(VERIFY).returncode, 0)

    def test_recreated_tenant_reseeds_same_objects(self):  # acceptance 3 (sandbox recreated)
        self.boot(); first = self.counts(); old = (self.d / "e.env").read_text()
        t2 = mg.Tenant(); s2 = mg.Server(t2)
        try:
            self.boot(srv=s2)
            self.assertEqual(self.counts(t2), first)
            self.assertNotEqual((self.d / "e.env").read_text(), old)
            self.assertIn(t2.id, (self.d / "e.env").read_text())
            self.assertEqual(self.run_s(VERIFY, srv=s2).returncode, 0)
            self.assertNotEqual(self.run_s(VERIFY, srv=self.srv).returncode, 0)  # old tenant no longer matches
        finally:
            s2.stop()

    def test_seeded_objects(self):
        self.boot(); t = self.tenant
        names = {u["mailNickname"] for u in t.c["users"]}
        self.assertTrue({"lab-user-01", "lab-disabled", "lab-admin-active", "lab-admin-eligible"} <= names)
        rag = [g for g in t.c["groups"] if g["displayName"] == "lab-rag-privileged"][0]
        self.assertTrue(rag["isAssignableToRole"])
        self.assertEqual(len(t.c["roleAssignments"]), 1); self.assertEqual(len(t.c["roleEligibilitySchedules"]), 1)

    def test_rotate_replaces_the_certificate(self):
        self.boot(); pem = (self.d / "e.pem").read_bytes()
        self.boot("--rotate"); self.assertNotEqual((self.d / "e.pem").read_bytes(), pem)
        self.assertEqual(len(self.tenant.c["applications"][0]["keyCredentials"]), 1)
        self.assertEqual(self.run_s(VERIFY).returncode, 0)

    def test_verify_fails_on_extra_permission(self):
        self.boot()
        sp = [s for s in self.tenant.c["servicePrincipals"] if s["appId"] != mg.GRAPH_APP][0]
        self.tenant.assign.append({"id": "x", "principalId": sp["id"], "resourceId": "r", "appRoleId": self.tenant.role_by_value("User.ReadWrite.All")["id"]})
        r = self.run_s(VERIFY); self.assertNotEqual(r.returncode, 0); self.assertIn("EXTRA permissions: User.ReadWrite.All", r.stderr)

    def test_verify_fails_on_missing_permission(self):
        self.boot()
        gid = self.tenant.role_by_value("Group.Create")["id"]
        self.tenant.assign[:] = [a for a in self.tenant.assign if a["appRoleId"] != gid]
        r = self.run_s(VERIFY); self.assertNotEqual(r.returncode, 0); self.assertIn("MISSING permissions: Group.Create", r.stderr)

    def test_verify_fails_on_directory_role_secret_or_wrong_cert(self):
        self.boot()
        sp = [s for s in self.tenant.c["servicePrincipals"] if s["appId"] != mg.GRAPH_APP][0]
        self.tenant.c["roleAssignments"].append({"id": "r", "principalId": sp["id"], "roleDefinitionId": "x"})
        self.assertIn("directory role", self.run_s(VERIFY).stderr)
        self.tenant.c["roleAssignments"].pop()
        self.tenant.c["applications"][0]["passwordCredentials"] = [{"keyId": "k"}]
        self.assertIn("client secret", self.run_s(VERIFY).stderr)
        self.tenant.c["applications"][0]["passwordCredentials"] = []
        self.tenant.c["applications"][0]["keyCredentials"] = [{"customKeyIdentifier": "00" * 20}]
        r = self.run_s(VERIFY); self.assertNotEqual(r.returncode, 0); self.assertIn("token refused", r.stderr)

    def test_verify_fails_on_loose_mode_or_missing_files(self):
        self.assertNotEqual(self.run_s(VERIFY).returncode, 0)
        self.boot(); os.chmod(self.d / "e.pem", 0o644)
        r = self.run_s(VERIFY); self.assertNotEqual(r.returncode, 0); self.assertIn("0600", r.stderr)

    def test_refuses_non_sandbox_domain(self):
        self.tenant.domain = "contoso.com"
        r = self.run_s(BOOT, "--yes"); self.assertNotEqual(r.returncode, 0); self.assertIn("refusing", r.stderr)
        self.assertFalse((self.d / "e.pem").exists())

    def test_interactive_confirmation_required_without_yes(self):
        env = dict(os.environ, GRAPH_BASE=self.srv.graph, LOGIN_BASE=self.srv.login, ENTRA_ENV=str(self.d / "e.env"),
                   ENTRA_PEM=str(self.d / "e.pem"), ENTRA_RETRY_SLEEP="0")
        r = subprocess.run([str(BOOT)], env=env, input="wrong\n", capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0); self.assertFalse((self.d / "e.pem").exists())

    def test_git_ignores_the_handover_files(self):
        for f in ("lab/.entra-lab.env", "lab/.entra-lab.pem"):
            r = subprocess.run(["git", "check-ignore", "-q", f], cwd=REPO); self.assertEqual(r.returncode, 0, f)


if __name__ == "__main__":
    unittest.main()
