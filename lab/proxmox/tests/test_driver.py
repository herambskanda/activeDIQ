"""T-1326 acceptance 2: the worker driver against a stub API. Scope refusals happen before the API is asked
to touch the VM; verify-scope fails closed; a TLS fingerprint mismatch sends nothing (not even the token)."""
import os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
import stubs
from stubs import P

DRIVER = Path(stubs.HERE).parent / "bin" / "proxmox-lab"


class DriverBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.cert, self.key, self.fpr = stubs.make_cert(self.d)
        self.statef = self.d / "state.json"
        self.envf = self.d / "lab.env"
        self.api = None

    def tearDown(self):
        if self.api: self.api.stop()
        shutil.rmtree(self.d)

    def start(self, state=None, secret=None, **env_over):
        st = state if state is not None else stubs.bootstrapped_state(self.fpr)[0]
        sec = st["tokens"][P.TOKEN_ID]["secret"]
        stubs.save(self.statef, st)
        self.secret = secret or sec
        self.api = stubs.StubApi(str(self.statef), self.cert, self.key)
        stubs.write_env(str(self.envf), "127.0.0.1", self.api.port, self.secret, self.fpr, **env_over)

    def run_drv(self, *args):
        env = dict(os.environ, PROXMOX_LAB_ENV=str(self.envf), PROXMOX_LAB_POLL="0")
        r = subprocess.run([sys.executable, str(DRIVER), *args], env=env, capture_output=True, text=True, timeout=60)
        self.assertNotIn(self.secret, r.stdout + r.stderr, "token secret leaked")
        return r

    def touched(self, vmid):
        return [q for q in self.api.requests if f"/qemu/{vmid}" in q["path"]]


class Scope(DriverBase):
    def test_list_shows_only_pool_members(self):
        self.start()
        r = self.run_drv("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("119\tdc1", r.stdout); self.assertNotIn("200", r.stdout)

    def test_every_vm_subcommand_refuses_a_vmid_outside_the_pool(self):
        self.start()
        for args in (("start", "200"), ("stop", "200"), ("stop", "200", "--graceful"), ("snapshots", "200"),
                     ("snapshot", "200", "s1"), ("rollback", "200", "s1"), ("attach-iso", "200", "local:iso/a.iso"),
                     ("attach-iso", "200", "--eject"), ("start", "201")):
            n = len(self.api.requests)
            r = self.run_drv(*args)
            self.assertEqual(r.returncode, 2, (args, r.stderr))
            self.assertIn("not a member of pool adiq-lab", r.stderr)
            self.assertEqual(self.touched(args[1]), [], f"{args} addressed the VM before the pool check")
            # the only call allowed is the pool read itself
            self.assertEqual({q["path"] for q in self.api.requests[n:]}, {"/api2/json/pools/adiq-lab"})

    def test_malformed_vmids_are_refused_without_any_request(self):
        self.start()
        for bad in ("12", "119;reboot", "119/../../200", "0119x", "-1", "1e3", " 119", "../119"):
            n = len(self.api.requests)
            r = self.run_drv("start", bad)
            self.assertIn(r.returncode, (2,), (bad, r.stderr))
            self.assertEqual(len(self.api.requests), n, bad)

    def test_pool_vm_operations_reach_the_api_with_typed_params(self):
        self.start()
        for args in (("start", "119"), ("stop", "119", "--graceful"), ("snapshot", "119", "clean", "--description", "x y"),
                     ("rollback", "119", "clean"), ("attach-iso", "119", "local:iso/win11.iso"), ("attach-iso", "119", "--eject")):
            r = self.run_drv(*args); self.assertEqual(r.returncode, 0, (args, r.stderr))
        got = [(q["method"], q["path"].removeprefix("/api2/json"), q["body"]) for q in self.api.requests if "/qemu/119" in q["path"] and "tasks" not in q["path"]]
        self.assertEqual(got, [("POST", f"/nodes/pve1/qemu/119/status/start", ""),
                               ("POST", "/nodes/pve1/qemu/119/status/shutdown", "timeout=120"),
                               ("POST", "/nodes/pve1/qemu/119/snapshot", "snapname=clean&vmstate=0&description=x+y"),
                               ("POST", "/nodes/pve1/qemu/119/snapshot/clean/rollback", ""),
                               ("PUT", "/nodes/pve1/qemu/119/config", "ide2=local%3Aiso%2Fwin11.iso%2Cmedia%3Dcdrom"),
                               ("PUT", "/nodes/pve1/qemu/119/config", "ide2=none%2Cmedia%3Dcdrom")])
        self.assertTrue(all(q["auth"] and q["auth"].startswith("PVEAPIToken=adiq-lab@pve!worker=") for q in self.api.requests))

    def test_injection_shaped_values_are_refused_before_the_api(self):
        self.start()
        for args in (("snapshot", "119", "a/../../b"), ("snapshot", "119", "x;y"), ("rollback", "119", "../../config"),
                     ("attach-iso", "119", "local:iso/a.iso,serial=x"), ("attach-iso", "119", "local:images/a.raw"),
                     ("create", "--name", "bad name"), ("create", "--name", "ok", "--iso", "x:iso/a.iso,media=disk"),
                     ("create", "--name", "ok", "--vmid", "200;1"), ("create", "--name", "ok", "--memory-mb", "99999999")):
            r = self.run_drv(*args); self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))
        self.assertEqual([q for q in self.api.requests if q["method"] != "GET"], [])

    def test_create_always_lands_in_the_pool(self):
        self.start()
        r = self.run_drv("create", "--name", "fs1", "--vmid", "310", "--iso", "local:iso/ws.iso", "--uefi-tpm")
        self.assertEqual(r.returncode, 0, r.stderr)
        post = [q for q in self.api.requests if q["method"] == "POST"][0]
        self.assertEqual(post["path"], "/api2/json/nodes/pve1/qemu")
        for frag in ("pool=adiq-lab", "vmid=310", "net0=virtio%2Cbridge%3Dvmbr0", "scsi0=local-lvm%3A60", "tpmstate0="):
            self.assertIn(frag, post["body"])
        self.assertEqual(self.run_drv("create", "--name", "dup", "--vmid", "119").returncode, 2)

    def test_task_failure_is_reported(self):
        self.start(); self.api.task_exit = "ERROR: boom"
        r = self.run_drv("start", "119"); self.assertEqual(r.returncode, 2); self.assertIn("task failed", r.stderr)


class Tls(DriverBase):
    def test_fingerprint_mismatch_sends_nothing(self):
        self.start()
        stubs.write_env(str(self.envf), "127.0.0.1", self.api.port, self.secret, "ab" * 32)
        for args in (("list",), ("start", "119"), ("verify-scope",)):
            r = self.run_drv(*args)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("fingerprint mismatch", r.stderr)
        self.assertEqual(self.api.requests, [], "an HTTP request (and so the token) went out to an unpinned server")

    def test_pin_accepts_colon_separated_uppercase(self):
        self.start()
        fp = ":".join(self.fpr[i:i + 2].upper() for i in range(0, 64, 2))
        stubs.write_env(str(self.envf), "127.0.0.1", self.api.port, self.secret, fp)
        self.assertEqual(self.run_drv("list").returncode, 0)

    def test_env_file_must_be_0600_and_complete(self):
        self.start(); os.chmod(self.envf, 0o640)
        r = self.run_drv("list"); self.assertEqual(r.returncode, 2); self.assertIn("0600", r.stderr)
        os.chmod(self.envf, 0o600)
        self.envf.write_text("PVE_HOST=127.0.0.1\n"); os.chmod(self.envf, 0o600)
        r = self.run_drv("list"); self.assertEqual(r.returncode, 2); self.assertIn("lacks", r.stderr)
        self.assertEqual(self.api.requests, [])


class VerifyScope(DriverBase):
    def expect_fail(self, needle, **kw):
        r = self.run_drv("verify-scope")
        self.assertEqual(r.returncode, 1, r.stderr); self.assertIn("verify-scope FAIL", r.stderr); self.assertIn(needle, r.stderr)

    def test_correct_token_passes(self):
        self.start(); r = self.run_drv("verify-scope")
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("verify-scope OK", r.stderr)

    def test_sees_vm_outside_the_pool(self):
        st, sec = stubs.bootstrapped_state(self.fpr, [{"path": "/vms/200", "roleid": P.ROLE}])
        self.start(st); self.expect_fail("VM 200"); self.expect_fail("/vms/200")

    def test_sys_privilege_anywhere(self):
        st, _ = stubs.bootstrapped_state(self.fpr, [{"path": f"/pool/{P.POOL}", "roleid": "SysRole"}])
        st["roles"]["SysRole"] = ["Sys.Audit"]; self.start(st); self.expect_fail("forbidden privilege Sys.Audit")

    def test_permissions_and_user_privileges(self):
        for priv in ("Permissions.Modify", "User.Modify", "Pool.Allocate"):
            with self.subTest(priv):
                st, _ = stubs.bootstrapped_state(self.fpr, [{"path": "/storage/local-lvm", "roleid": "Bad"}])
                st["roles"]["Bad"] = [priv]
                if self.api: self.api.stop()
                self.start(st); self.expect_fail(f"forbidden privilege {priv}")

    def test_acl_on_root_or_vms(self):
        for path in ("/", "/vms"):
            with self.subTest(path):
                st, _ = stubs.bootstrapped_state(self.fpr, [{"path": path, "roleid": P.ROLE}])
                if self.api: self.api.stop()
                self.start(st); self.expect_fail(f"outside the pool")

    def test_privilege_not_in_the_lab_role(self):
        st, _ = stubs.bootstrapped_state(self.fpr, [{"path": "/storage/local-lvm", "roleid": "Bad"}])
        st["roles"]["Bad"] = ["Datastore.Allocate"]; self.start(st); self.expect_fail("Datastore.Allocate")

    def test_other_pool_visible(self):
        st, _ = stubs.bootstrapped_state(self.fpr, [{"path": "/pool/prod", "roleid": P.ROLE}])
        st["pools"]["prod"] = {"members": [200]}; self.start(st); self.expect_fail("pool prod")

    def test_dc1_must_be_in_the_pool(self):
        st, _ = stubs.bootstrapped_state(self.fpr); st["pools"][P.POOL]["members"] = []
        self.start(st); self.expect_fail("VM 119 (dc1) is not in pool")

    def test_api_error_fails_closed(self):
        self.start(); self.api.fail_path = "/access/permissions"; self.expect_fail("failing closed")

    def test_wrong_token_fails(self):
        self.start(secret="00000000-0000-0000-0000-000000000000")
        r = self.run_drv("verify-scope"); self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
