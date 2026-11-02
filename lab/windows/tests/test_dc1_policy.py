"""Offline proof for T-1265: dc1 must stay at LDAPServerIntegrity=2 / LdapEnforceChannelBindingTokens=2, and every
lab tool that needs it stops before testing when it is not. No Windows and no WinRM: the DC is a fake `ps` callable.

Each check has a failing counterpart (the first test of each group drives the broken shape) so the guard is shown to bite.
"""
import importlib.machinery, importlib.util, os, re, subprocess, sys, tempfile, unittest
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

    def __init__(self, integrity=2, cbt=2):
        self.integrity, self.cbt, self.sent = integrity, cbt, []

    def ps(self, script):
        self.sent.append(script)
        if "LDAPServerIntegrity" in script and "GetValue" in script:
            return 0, f"LDAPServerIntegrity = {self.integrity}\nLdapEnforceChannelBindingTokens = {self.cbt}"
        if "UtcNow" in script:
            return 0, "2026-11-02T06:00:00.0000000Z"
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

    def test_run_that_leaves_policy_changed_fails(self):
        class Drifting(FakeDC):
            def ps(self, script):
                r = super().ps(script)
                if "Set-Date" in script:
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


if __name__ == "__main__":
    unittest.main()
