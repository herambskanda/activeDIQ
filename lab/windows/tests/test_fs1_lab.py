"""Offline proof of fs1-lab's judge and PowerShell builders (T-1328). Each acceptance check must FAIL on a violation."""
import os, sys, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import fs1lab

GOOD = {
    "PartOfDomain": "True", "Domain": "win.activediq.test", "NLTEST": "Flags: 0 | Trusted DC Connection Status Status = 0 0x0 NERR_Success",
    "Test-ADServiceAccount": "True", "ADMINS": "FS1\\Administrator,WIN\\Domain Admins", "USERS": "NT AUTHORITY\\INTERACTIVE,FS1\\adiq-std",
    "LOCALUSER_ENABLED": "True", "DNS": "192.168.1.250", "DHCP": "Disabled", "NIC": "Red Hat VirtIO Ethernet Adapter",
}


class Judge(unittest.TestCase):
    def test_good_passes(self):
        self.assertEqual(fs1lab.problems(GOOD), [])

    def fails(self, **change):
        ev = dict(GOOD, **change)
        self.assertTrue(fs1lab.problems(ev), change)

    def test_each_violation_is_caught(self):
        self.fails(PartOfDomain="False")
        self.fails(Domain="WORKGROUP")
        self.fails(NLTEST="Status = 1722 ERROR_RPC_S_SERVER_UNAVAILABLE")
        self.fails(**{"Test-ADServiceAccount": "False"})
        self.fails(ADMINS="FS1\\Administrator,FS1\\adiq-std")
        self.fails(USERS="NT AUTHORITY\\INTERACTIVE")
        self.fails(LOCALUSER_ENABLED="False")
        self.fails(DNS="192.168.1.1")
        self.fails(DHCP="Enabled")
        self.fails(NIC="Intel e1000")


class Quote(unittest.TestCase):
    def test_refuses_metacharacters(self):
        for v in ("a'b", "a;b", "a b", "$(x)", "a`b", ""):
            with self.assertRaises(ValueError):
                fs1lab.ps_quote(v)

    def test_secret_charset(self):
        for v in ("short", "ctrl\n123456789012", "uni\u00e9code123456789"):
            with self.assertRaises(ValueError):
                fs1lab.ps_secret(v)
        self.assertEqual(fs1lab.ps_secret("it's;$(x)123456"), "'it''s;$(x)123456'")

    def test_user_script_never_admin(self):
        s = fs1lab.user_ps("Abcdefghijklmnop1234")
        self.assertIn("Remove-LocalGroupMember -Group 'Administrators'", s)
        self.assertNotIn("Add-LocalGroupMember -Group 'Administrators'", s)

    def test_parse(self):
        self.assertEqual(fs1lab.parse_kv("A=1\nnoise\nB=x=y\n"), {"A": "1", "B": "x=y"})


if __name__ == "__main__":
    unittest.main()
