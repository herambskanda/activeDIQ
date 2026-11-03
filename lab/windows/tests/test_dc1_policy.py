"""Offline proof for T-1265: dc1 must stay at LDAPServerIntegrity=2 / LdapEnforceChannelBindingTokens=2, and every
lab tool that needs it stops before testing when it is not. No Windows and no WinRM: the DC is a fake `ps` callable.

Each check has a failing counterpart (the first test of each group drives the broken shape) so the guard is shown to bite.
"""
import datetime, importlib.machinery, importlib.util, os, re, subprocess, sys, tempfile, unittest
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB / "lib"))

SIGNING = re.compile(r"LDAPServerIntegrity|LDAP Server Integrity", re.I)


def load_gssapi_lab(env_dir):
    """Import bin/gssapi-lab as a module with a throw-away lab env file (no network, no secrets)."""
    envf = Path(env_dir) / ".win-lab.env"
    envf.write_text('WIN_LAB_ADMIN_PASSWORD="x"\nWIN_LAB_DC_ADDR="192.0.2.1"\n')
    os.environ["WIN_LAB_ENV"] = str(envf)
    loader = importlib.machinery.SourceFileLoader("gssapi_lab_under_test", str(LAB / "bin" / "gssapi-lab"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class FakeDC:
    """Answers the registry read of gssapi-lab.policy() and records every WinRM script it is sent."""

    def __init__(self, integrity=2, cbt=2, gpo=2):
        self.integrity, self.cbt, self.gpo, self.sent = integrity, cbt, gpo, []

    def ps(self, script):
        self.sent.append(script)
        if "GPO_LDAPServerIntegrity" in script:
            return 0, f"GPO_LDAPServerIntegrity = 4,{self.gpo}" if self.gpo is not None else "GPO_LDAPServerIntegrity = "
        if "LDAPServerIntegrity" in script and "GetValue" in script:
            return 0, f"LDAPServerIntegrity = {self.integrity}\nLdapEnforceChannelBindingTokens = {self.cbt}"
        if "UtcNow" in script:
            return 0, datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"  # dc1 in step (NTP, T-0850)
        return 0, ""


class RunStopsBeforeTesting(unittest.TestCase):
    """AC3: `gssapi-lab run` with dc1 not at 2/2 must not start `go test`, must change nothing on dc1, and must name the value."""

    def run_with(self, dc):
        with tempfile.TemporaryDirectory() as d:
            m = load_gssapi_lab(d)
            ran = []
            m.ps = dc.ps
            m.time = type("T", (), {"sleep": staticmethod(lambda s: None)})
            m.subprocess = type("S", (), {"run": staticmethod(lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0))})
            try:
                m.run(["-run", "X", "./x/"])
                code = 0
            except SystemExit as e:
                code = e.code
            return code, ran

    def test_signing_negotiated_stops_run_and_names_value(self):
        dc = FakeDC(integrity=1)
        code, ran = self.run_with(dc)
        self.assertEqual(ran, [], "go test was started although dc1 reads LDAPServerIntegrity=1")
        self.assertIn("LDAPServerIntegrity", str(code))
        self.assertIn("1", str(code))
        self.assertFalse([s for s in dc.sent if "Set-Date" in s or "Set-ItemProperty" in s], "run changed dc1 before refusing")

    def test_cbt_not_always_stops_run_and_names_value(self):
        code, ran = self.run_with(FakeDC(cbt=1))
        self.assertEqual(ran, [])
        self.assertIn("LdapEnforceChannelBindingTokens", str(code))

    def test_absent_value_stops_run(self):
        code, ran = self.run_with(FakeDC(integrity="", cbt=2))
        self.assertEqual(ran, [])
        self.assertIn("LDAPServerIntegrity", str(code))

    def test_run_proceeds_when_policy_is_2_2(self):
        code, ran = self.run_with(FakeDC())
        self.assertEqual(len(ran), 1, "go test should start when dc1 is at 2/2")

    def test_run_refuses_when_dc1_clock_is_far_off_and_never_steps_it(self):  # T-0850
        class Skewed(FakeDC):
            def ps(self, script):
                r = super().ps(script)
                if "UtcNow" in script:
                    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12, minutes=30)
                    return 0, t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
                return r
        dc = Skewed()
        code, ran = self.run_with(dc)
        self.assertEqual(ran, [], "go test must not start with dc1's clock 12h30m off")
        self.assertIn("KRB_AP_ERR_SKEW", str(code))
        self.assertFalse([x for x in dc.sent if "Set-Date" in x], "gssapi-lab must not step dc1's clock")

    def test_run_that_leaves_policy_changed_fails(self):
        class Drifting(FakeDC):
            def ps(self, script):
                r = super().ps(script)
                if "Set-ItemProperty" in script and "Diagnostics" in script and "Value 2" in script:
                    self.integrity = 1  # something resets it during the run
                return r
        code, ran = self.run_with(Drifting())
        self.assertNotEqual(code, 0)
        self.assertIn("LDAPServerIntegrity", str(code))


class PolicyCheck(unittest.TestCase):
    def setUp(self):
        import dc1policy
        self.p = dc1policy

    def test_parse_and_problems(self):
        v = self.p.parse_policy("LDAPServerIntegrity = 1\nLdapEnforceChannelBindingTokens = 2\n")
        self.assertEqual(v, {"LDAPServerIntegrity": 1, "LdapEnforceChannelBindingTokens": 2})
        self.assertEqual(self.p.problems(v), ["LDAPServerIntegrity is 1, need 2"])
        self.assertEqual(self.p.problems({"LDAPServerIntegrity": 2, "LdapEnforceChannelBindingTokens": 2}), [])
        self.assertEqual(self.p.problems(self.p.parse_policy("LDAPServerIntegrity = \nLdapEnforceChannelBindingTokens = 2")),
                         ["LDAPServerIntegrity is absent, need 2"])

    def test_bind_probe_reads_result_code(self):
        import socket, threading
        for code, want in ((8, "strongerAuthRequired"), (49, "invalidCredentials")):
            srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
            resp = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00])

            def serve():
                c, _ = srv.accept(); c.recv(4096); c.sendall(resp); c.close()
            threading.Thread(target=serve, daemon=True).start()
            self.assertEqual(self.p.bind_probe("127.0.0.1", port=srv.getsockname()[1]), (code, want))
            srv.close()


class NoScriptCanLeaveWeakSigning(unittest.TestCase):
    """AC2: scan every lab file that writes the value. The scan itself is proved on bad fixtures first."""

    WRITE = re.compile(r"(Set-ItemProperty|New-ItemProperty|reg(\.exe)?\s+add|SetValue\(|Set-Item\b)", re.I)
    # a value literal next to its name: @('LDAPServerIntegrity', 2)  |  -Name LDAPServerIntegrity -Value 1  |  /v LDAPServerIntegrity /d 0
    PAIR = re.compile(r"(?:LDAPServerIntegrity|LDAP Server Integrity)['\"]?\s*(?:,|(?:-Type\s+\w+\s+)?-Value|/t\s+\w+\s+/d|/d)\s*(\d+)", re.I)

    @classmethod
    def weak_writes(cls, text):
        """Values other than 2 written for the signing key in a file that writes registry values; [] if clean."""
        if not (SIGNING.search(text) and cls.WRITE.search(text)):
            return None  # does not write the value at all
        return [m for m in cls.PAIR.findall(text) if m != "2"]

    def test_scanner_flags_a_script_that_writes_1_or_0(self):
        for bad in ("Set-ItemProperty $n -Name LDAPServerIntegrity -Type DWord -Value 1",
                    "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity /d 0 /f",
                    "foreach ($kv in @(@('LDAPServerIntegrity', 1))) { Set-ItemProperty $ntds -Name $kv[0] -Value $kv[1] }"):
            self.assertTrue(self.weak_writes(bad), bad)
        self.assertEqual(self.weak_writes("foreach ($kv in @(@('LDAPServerIntegrity', 2))) { Set-ItemProperty $n -Name $kv[0] -Value $kv[1] }"), [])
        self.assertIsNone(self.weak_writes("(Get-Item $n).GetValue('LDAPServerIntegrity')"))

    def test_repo_lab_tooling_only_writes_2(self):
        writers = []
        for root in (LAB, LAB.parent / "e2e"):
            for p in root.rglob("*"):
                if not p.is_file() or "tests" in p.parts or "__pycache__" in p.parts or p.name.startswith("."):
                    continue
                try:
                    text = p.read_text()
                except UnicodeDecodeError:
                    continue
                weak = self.weak_writes(text)
                if weak is not None:
                    writers.append(p.name)
                    self.assertEqual(weak, [], f"{p} writes LDAPServerIntegrity={weak}; only 2 is allowed")
        self.assertIn("gssapi-ready.ps1", writers, "scanner is blind: gssapi-ready.ps1 writes the value")

    def test_gssapi_ready_always_ends_by_asserting_2_2(self):
        s = (LAB / "guest" / "gssapi-ready.ps1").read_text()
        self.assertIn("finally", s, "gssapi-ready.ps1 must assert the policy in a finally block")
        tail = s[s.rindex("finally"):]
        self.assertRegex(tail, r"LDAPServerIntegrity")
        self.assertRegex(tail, r"throw")



def load_cli():
    loader = importlib.machinery.SourceFileLoader("dc1_policy_cli", str(LAB / "bin" / "dc1-policy"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Cli(unittest.TestCase):
    """dc1-policy check/restore against a fake DC and a fake LDAP port."""

    def fake_ldap(self, code):
        import socket, threading
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
        resp = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00])

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                c.recv(4096); c.sendall(resp); c.close()
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(srv.close)
        return srv.getsockname()[1]

    def test_check_names_both_registry_and_wire_failures(self):
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(49)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        bad = cli.check(FakeDC(integrity=1).ps, "127.0.0.1", lambda m: None)
        self.assertIn("LDAPServerIntegrity is 1, need 2", bad)
        self.assertTrue(any("answered 49" in b for b in bad), bad)

    def test_check_passes_only_when_2_2_and_bind_8(self):
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(8)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        self.assertEqual(cli.check(FakeDC().ps, "127.0.0.1", lambda m: None, "pw"), [])

    def test_restore_writes_only_2_and_reboots_only_when_it_changed(self):
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(8)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        cli.wait_for_dc = lambda ps, tries=90: True

        class Dc(FakeDC):
            def ps(self, script):
                self.sent.append(script)
                if "Set-ItemProperty" in script and "GptTmpl" not in script:
                    self.integrity = self.cbt = 2
                    return 0, ""
                if "GptTmpl" in script and "Set-Content" in script:
                    self.gpo = 2
                    return 0, ""
                return super().ps(script)

        dc = Dc(integrity=1)
        self.assertEqual(cli.restore(dc.ps, "127.0.0.1", lambda m: None, "pw"), [])
        writes = [s for s in dc.sent if "Set-ItemProperty" in s and "GptTmpl" not in s]
        self.assertEqual(len(writes), 1)
        self.assertEqual(sorted(re.findall(r"-Value (\d+)", writes[0])), ["2", "2"])
        self.assertTrue([s for s in dc.sent if "shutdown" in s])
        ok = Dc()
        self.assertEqual(cli.restore(ok.ps, "127.0.0.1", lambda m: None, "pw"), [])
        self.assertFalse([s for s in ok.sent if "Set-ItemProperty" in s or "Set-Content" in s or "shutdown" in s],
                         "restore touched a healthy dc1")

    def test_dummy_credentials_cannot_pass_the_check(self):
        """Measured on dc1 at 2/2: a dummy-credential bind answers 49, so only a valid-account bind can prove enforcement."""
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(8)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        bad = cli.check(FakeDC().ps, "127.0.0.1", lambda m: None)
        self.assertTrue(any("WIN_LAB_SVC_PASSWORD" in b for b in bad), bad)

    def test_gpo_defining_1_is_a_failure_even_when_the_registry_reads_2(self):
        """T-1265 root cause: the Default Domain Controllers Policy template says 4,1 and rewrites the registry at boot/refresh."""
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(8)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        bad = cli.check(FakeDC(gpo=1).ps, "127.0.0.1", lambda m: None, "pw")
        self.assertTrue(any("Default Domain Controllers Policy" in b and "1" in b for b in bad), bad)
        self.assertTrue(cli.check(FakeDC(gpo=None).ps, "127.0.0.1", lambda m: None, "pw"))

    def test_restore_fixes_the_gpo_template_even_when_the_registry_is_already_2(self):
        import dc1policy
        cli = load_cli()
        port = self.fake_ldap(8)
        orig = dc1policy.bind_probe
        dc1policy.bind_probe = lambda host, port=port, timeout=10, **kw: orig(host, port=port, timeout=timeout, **kw)
        self.addCleanup(setattr, dc1policy, "bind_probe", orig)
        cli.wait_for_dc = lambda ps, tries=90: True

        class Dc(FakeDC):
            def ps(self, script):
                if "GptTmpl" in script and "Set-Content" in script:
                    self.sent.append(script)
                    self.gpo = 2
                    return 0, ""
                return super().ps(script)

        dc = Dc(gpo=1)
        self.assertEqual(cli.restore(dc.ps, "127.0.0.1", lambda m: None, "pw"), [])
        fix = [s for s in dc.sent if "Set-Content" in s]
        self.assertEqual(len(fix), 1)
        self.assertIn("LDAPServerIntegrity=4,2", fix[0])
        self.assertNotIn("LDAPServerIntegrity=4,1", fix[0])


if __name__ == "__main__":
    unittest.main()
