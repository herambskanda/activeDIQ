"""T-1326 acceptances 1 and 3: bootstrap and revoke, run for real against a fake ssh + fake pveum/pvesh
(one JSON state file) and the stub API. The remote commands are the real ones; only Proxmox is simulated."""
import ast, os, re, shlex, shutil, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
import stubs
from stubs import P

BIN = Path(stubs.HERE).parent / "bin"
BOOT = BIN / "proxmox-lab-bootstrap"
REPO = Path(stubs.HERE).parents[2]
MUTATING = {("pool", "add"), ("pool", "modify"), ("role", "add"), ("role", "modify"), ("role", "delete"), ("user", "add"),
            ("user", "delete"), ("user", "token"), ("acl", "modify"), ("acl", "delete")}


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.cert, self.key, self.fpr = stubs.make_cert(self.d)
        self.statef, self.logf, self.envf = self.d / "state.json", self.d / "ssh.log", self.d / "lab.env"
        stubs.save(self.statef, stubs.initial_state(self.fpr))
        self.ssh = stubs.install_fakes(self.d / "bin", self.statef, self.logf)
        self.api = stubs.StubApi(str(self.statef), self.cert, self.key)

    def tearDown(self):
        self.api.stop(); shutil.rmtree(self.d)

    def run_b(self, *args, host="127.0.0.1", ssh=None):
        env = dict(os.environ, PVE_HOST=host, PROXMOX_LAB_SSH=str(ssh or self.ssh), PROXMOX_LAB_ENV=str(self.envf),
                   PROXMOX_LAB_POLL="0", XDG_RUNTIME_DIR=str(self.d))
        r = subprocess.run([sys.executable, str(BOOT), *args], env=env, capture_output=True, text=True, timeout=120)
        sec = self.secret()
        if sec: self.assertNotIn(sec, r.stdout + r.stderr, "token secret leaked to stdout/stderr")
        return r

    def bootstrap(self, *extra):
        r = self.run_b("bootstrap", "--port", str(self.api.port), *extra)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr); return r

    def state(self): return stubs.load(self.statef)

    def secret(self):
        t = self.state()["tokens"].get(P.TOKEN_ID)
        return t["secret"] if t else None

    def ssh_cmds(self):
        return [ast.literal_eval(l)[2] for l in self.logf.read_text().splitlines()] if self.logf.exists() else []

    def mutations(self):
        return [c for c in self.state()["log"] if c[0] == "pveum" and tuple(c[1:3]) in MUTATING]


class Bootstrap(Base):
    def test_creates_exactly_the_pool_user_role_token_and_acls(self):  # acceptance 1
        r = self.bootstrap()
        st = self.state()
        self.assertEqual(st["pools"][P.POOL]["members"], [119])
        self.assertEqual(st["roles"][P.ROLE], list(P.WORKER_PRIVS))
        self.assertIn(P.USER, st["users"])
        self.assertEqual(st["tokens"][P.TOKEN_ID]["privsep"], "1")
        mine = {(e["path"], e["roleid"]) for e in st["acl"] if e["ugid"] in (P.USER, P.TOKEN_ID)}
        # the VM's disk storage (local-lvm) has no ISO content, so the only ISO store (local) is found and gets the read-only role
        self.assertEqual(mine, {(f"/pool/{P.POOL}", P.ROLE), ("/storage/local-lvm", P.ROLE), ("/sdn/zones/localnetwork/vmbr0", P.ROLE),
                                ("/storage/local", P.ISO_ROLE)})
        self.assertEqual(st["roles"][P.ISO_ROLE], ["Datastore.Audit"])
        for path in ("/", "/vms"):  # no ACL for our principals on / or /vms, and the pre-existing root ACL is untouched
            self.assertEqual([e for e in st["acl"] if e["path"] == path and e["ugid"] in (P.USER, P.TOKEN_ID)], [])
        # both the user and the token carry every ACL (privsep tokens get the intersection)
        for path, _ in mine:
            self.assertEqual({e["ugid"] for e in st["acl"] if e["path"] == path}, {P.USER, P.TOKEN_ID})
        for bad in P.FORBIDDEN_PREFIXES:
            self.assertFalse([p for p in st["roles"][P.ROLE] if p.startswith(bad)])
        self.assertIn("verify-scope OK", r.stderr)

    def test_env_file_is_0600_complete_and_the_secret_is_never_printed(self):
        r = self.bootstrap()
        self.assertEqual(stat.S_IMODE(self.envf.stat().st_mode), 0o600)
        env = dict(l.split("=", 1) for l in self.envf.read_text().splitlines() if "=" in l and not l.startswith("#"))
        self.assertEqual(env["PVE_TOKEN_SECRET"], self.secret())
        self.assertEqual(env["PVE_CERT_SHA256"], self.fpr)
        self.assertEqual({k: env[k] for k in ("PVE_HOST", "PVE_NODE", "PVE_TOKEN_ID", "PVE_POOL", "PVE_STORAGE", "PVE_BRIDGE")},
                         {"PVE_HOST": "127.0.0.1", "PVE_NODE": "pve1", "PVE_TOKEN_ID": P.TOKEN_ID, "PVE_POOL": P.POOL,
                          "PVE_STORAGE": "local-lvm", "PVE_BRIDGE": "vmbr0"})
        self.assertNotIn(self.secret(), r.stdout + r.stderr)
        self.assertNotIn(self.secret(), self.logf.read_text())             # not in any remote command line
        self.assertNotIn(self.secret(), " ".join(map(str, self.state()["log"])))
        self.assertEqual([f for f in os.listdir(self.d) if f.startswith(".")], [], "temp env file left behind")

    def test_env_file_and_ignore_rule(self):
        for path in ("lab/.proxmox-lab.env",):
            r = subprocess.run(["git", "-C", str(REPO), "check-ignore", "-v", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, "lab/.proxmox-lab.env is not git-ignored"); print(r.stdout.strip())

    def test_every_remote_command_is_one_shell_safe_argv(self):
        self.bootstrap()
        cmds = self.ssh_cmds()
        self.assertTrue(cmds)
        for c in cmds:
            argv = shlex.split(c)
            self.assertIn(argv[0], {"pveum", "pvesh", "pveversion"}, c)
            self.assertEqual(shlex.join(argv), c)      # quoting round-trips: nothing is left to the remote shell to interpret
        self.assertFalse([c for c in cmds if re.search(r"\bqm\b|/qemu/\d+/(status|snapshot)", c)])

    def test_rerun_keeps_the_token_and_rotate_replaces_it(self):
        self.bootstrap(); first = self.secret(); env1 = self.envf.read_text()
        r = self.bootstrap(); self.assertIn("keeping it", r.stdout)
        self.assertEqual(self.secret(), first); self.assertEqual(self.envf.read_text(), env1)
        self.bootstrap("--rotate"); self.assertNotEqual(self.secret(), first)
        self.assertIn(self.secret(), self.envf.read_text()); self.assertNotIn(first, self.envf.read_text())

    def test_lost_env_file_recreates_the_token(self):
        self.bootstrap(); first = self.secret(); self.envf.unlink()
        self.bootstrap(); self.assertNotEqual(self.secret(), first); self.assertTrue(self.envf.exists())

    def test_unexpected_acls_on_our_principals_are_removed(self):
        st = self.state()
        st["users"][P.USER] = {}
        st["roles"]["Administrator"] = ["Sys.Audit"]
        st["acl"].append({"path": "/", "roleid": "Administrator", "type": "user", "ugid": P.USER, "propagate": 1})
        st["acl"].append({"path": "/vms", "roleid": "Administrator", "type": "token", "ugid": P.TOKEN_ID, "propagate": 1})
        stubs.save(self.statef, st)
        r = self.bootstrap(); self.assertIn("removing unexpected ACL / ", r.stdout)
        left = {(e["path"]) for e in self.state()["acl"] if e["ugid"] in (P.USER, P.TOKEN_ID)}
        self.assertEqual(left, {f"/pool/{P.POOL}", "/storage/local-lvm", "/sdn/zones/localnetwork/vmbr0", "/storage/local"})
        self.assertTrue([e for e in self.state()["acl"] if e["ugid"] == "root@pam"], "someone else's ACL was touched")

    def test_iso_on_the_lab_storage_needs_no_second_role(self):
        self.bootstrap("--iso-storage", "local-lvm")
        st = self.state()
        self.assertNotIn(P.ISO_ROLE, st["roles"])
        self.assertEqual({e["path"] for e in st["acl"] if e["ugid"] == P.TOKEN_ID},
                         {f"/pool/{P.POOL}", "/storage/local-lvm", "/sdn/zones/localnetwork/vmbr0"})

    def test_certificate_the_api_serves_must_match_the_node_certificate(self):  # pin cannot be planted by a wrong address
        st = self.state(); st["certs"][0]["fingerprint"] = "AB:" * 31 + "AB"; stubs.save(self.statef, st)
        r = self.run_b("bootstrap", "--port", str(self.api.port))
        self.assertEqual(r.returncode, 2); self.assertIn("not the node's", r.stderr)
        self.assertEqual(self.mutations(), []); self.assertFalse(self.envf.exists())

    def test_old_proxmox_and_missing_vm_are_refused_before_any_change(self):
        st = self.state(); st["version"] = "pve-manager/7.4.1/x"; stubs.save(self.statef, st)
        r = self.run_b("bootstrap", "--port", str(self.api.port)); self.assertEqual(r.returncode, 2); self.assertIn("8 or newer", r.stderr)
        st["version"] = "pve-manager/8.2.4/x"; stubs.save(self.statef, st)
        r = self.run_b("bootstrap", "--port", str(self.api.port), "--vmid", "555"); self.assertEqual(r.returncode, 2); self.assertIn("555 not found", r.stderr)
        self.assertEqual(self.mutations(), []); self.assertFalse(self.envf.exists())

    def test_hostile_host_and_names_never_reach_ssh(self):
        for host in ("a;reboot", "-oProxyCommand=x", "h st", "$(id)", "", "a" * 300):
            r = self.run_b("bootstrap", host=host)
            self.assertEqual(r.returncode, 2, host)
        for extra in (["--storage", "x;y"], ["--bridge", "$(id)"], ["--vmid", "119 120"], ["--iso-storage", "../x"]):
            r = self.run_b("bootstrap", "--port", str(self.api.port), *extra); self.assertEqual(r.returncode, 2, extra)
        self.assertEqual(self.mutations(), [])
        for c in self.ssh_cmds():
            self.assertNotIn(";", c.replace("';'", "")); self.assertNotIn("$(", c)

    def test_dry_run_prints_the_exact_commands_and_runs_nothing(self):
        r = self.run_b("bootstrap", "--dry-run", host="192.0.2.10")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.ssh_cmds(), []); self.assertFalse(self.envf.exists()); self.assertEqual(self.state()["log"], [])
        for frag in ("pveum pool add adiq-lab", "pveum pool modify adiq-lab --vms 119", "pveum role add AdiqLabWorker --privs",
                     "pveum user add adiq-lab@pve", "pveum user token add adiq-lab@pve worker --privsep 1",
                     "pveum acl modify /pool/adiq-lab --roles AdiqLabWorker --users adiq-lab@pve --tokens 'adiq-lab@pve!worker' --propagate 1",
                     "pvesh get /access/acl --output-format json"):
            self.assertIn(frag, r.stdout)
        for forbidden in ("Sys.", "Permissions.", "User.Modify", "Pool.Allocate", "acl modify / ", "acl modify /vms "):
            self.assertNotIn(forbidden, r.stdout)
        print(r.stdout)

    def assert_bootstrap_refuses_to_bless(self, r, needle):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("verify-scope FAIL", r.stderr); self.assertIn(needle, r.stderr)
        self.assertIn("verify-scope FAILED. The token is NOT safe to use; run `make proxmox-lab-revoke`", r.stderr)
        self.assertNotIn("== done", r.stdout)

    def test_bootstrap_exits_nonzero_when_the_token_turns_out_too_wide(self):
        # an ACL on the token that the reconcile step cannot see (hidden from `pvesh get /access/acl`) widens it
        st = self.state(); st["roles"]["Bad"] = ["Sys.Modify"]
        st["acl"].append({"path": "/", "roleid": "Bad", "type": "token", "ugid": P.TOKEN_ID, "propagate": 1, "hidden": True})
        stubs.save(self.statef, st)
        self.assert_bootstrap_refuses_to_bless(self.run_b("bootstrap", "--port", str(self.api.port)), "forbidden privilege Sys.Modify")

    def test_bootstrap_exits_nonzero_when_the_token_cannot_be_verified(self):
        self.api.fail_path = "/access/permissions"      # fails closed: an unreadable scope is not a safe scope
        self.assert_bootstrap_refuses_to_bless(self.run_b("bootstrap", "--port", str(self.api.port)), "failing closed")


class Revoke(Base):
    def test_revoke_removes_everything_and_touches_no_vm(self):  # acceptance 3
        self.bootstrap()
        before = {k: self.state()[k] for k in ("vms", "config", "snapshots")}
        pool_before = self.state()["pools"][P.POOL]["members"]
        self.logf.write_text("")
        r = self.run_b("revoke"); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.state()
        self.assertNotIn(P.USER, st["users"]); self.assertEqual(st["tokens"], {})
        self.assertNotIn(P.ROLE, st["roles"]); self.assertNotIn(P.ISO_ROLE, st["roles"])
        self.assertEqual([e for e in st["acl"] if e["ugid"] in (P.USER, P.TOKEN_ID)], [])
        self.assertTrue([e for e in st["acl"] if e["ugid"] == "root@pam"])
        self.assertFalse(self.envf.exists())
        self.assertEqual({k: st[k] for k in before}, before)                  # every VM, config and snapshot untouched
        self.assertEqual(st["pools"][P.POOL]["members"], pool_before)         # pool and membership untouched
        for c in self.ssh_cmds():
            self.assertNotEqual("qm", shlex.split(c)[0]); self.assertNotRegex(c, r"/qemu/|pool (add|modify|delete)|--vms")
        self.assertIn("VMs and pool adiq-lab were not touched", r.stdout)

    def test_revoke_is_idempotent(self):
        self.bootstrap(); self.assertEqual(self.run_b("revoke").returncode, 0)
        r = self.run_b("revoke"); self.assertEqual(r.returncode, 0, r.stderr)

    def test_revoke_with_separate_iso_storage(self):
        self.bootstrap("--iso-storage", "local"); self.assertEqual(self.run_b("revoke").returncode, 0)
        self.assertEqual([e for e in self.state()["acl"] if e["ugid"] in (P.USER, P.TOKEN_ID)], [])
        self.assertNotIn(P.ISO_ROLE, self.state()["roles"])

    def test_revoked_token_is_dead_at_the_api(self):
        self.bootstrap(); sec = self.secret(); stubs.write_env(str(self.d / "old.env"), "127.0.0.1", self.api.port, sec, self.fpr)
        self.run_b("revoke")
        r = subprocess.run([sys.executable, str(BIN / "proxmox-lab"), "list"], env=dict(os.environ, PROXMOX_LAB_ENV=str(self.d / "old.env")),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2); self.assertIn("401", r.stderr)

    def test_revoke_dry_run(self):
        self.bootstrap(); self.logf.write_text(""); n = len(self.state()["log"])
        r = self.run_b("revoke", "--dry-run", host="192.0.2.10"); self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.ssh_cmds(), []); self.assertEqual(len(self.state()["log"]), n); self.assertTrue(self.envf.exists())
        for frag in ("pveum acl delete /pool/adiq-lab --roles AdiqLabWorker --users adiq-lab@pve",
                     "pveum acl delete /storage/local-lvm", "pveum acl delete /sdn/zones/localnetwork/vmbr0",
                     "pveum user token remove adiq-lab@pve worker", "pveum user delete adiq-lab@pve", "pveum role delete AdiqLabWorker"):
            self.assertIn(frag, r.stdout)
        self.assertNotIn("qm ", r.stdout); self.assertNotRegex(r.stdout, r"pool (delete|modify)")
        print(r.stdout)


if __name__ == "__main__":
    unittest.main()
