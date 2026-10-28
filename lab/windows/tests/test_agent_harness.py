"""Offline guard for the T-0613 agent-identity harness (no Windows needed): the script must pin exactly the
ADR-0006 identity and must not use unsafe primitives. Real proof is the lab run (runbook windows-lab.md §11)."""
import re, unittest
from pathlib import Path

S = (Path(__file__).resolve().parent.parent / "agent-harness/Install-AgentLabHarness.ps1").read_text()


class AgentHarness(unittest.TestCase):
    def test_adr0006_identity_pinned(self):
        self.assertIn('"NT SERVICE\\$Name"', S)
        self.assertIn("'sidtype', $Name, 'restricted'", S)
        self.assertRegex(S, r"\$Pinned\s*=\s*@\('SeChangeNotifyPrivilege'\)")

    def test_never_localsystem_or_dangerous_privs(self):
        self.assertNotRegex(S, r"obj=',\s*'LocalSystem")
        for p in ("SeDebug", "SeBackup", "SeRestore", "SeTcb", "SeImpersonate", "SeTakeOwnership", "SeLoadDriver"):
            self.assertNotIn(p, S)

    def test_no_string_built_commands(self):
        self.assertNotRegex(S, r"Invoke-Expression|\biex\b|cmd(\.exe)?\s+/c|-Command\s+\"")
        self.assertNotRegex(S, r"SDDL\s*=\s*[\"'].*\$")  # no interpolated SDDL
        self.assertIn("DirectorySecurity", S)  # typed ACL API

    def test_uninstall_leaves_nothing(self):
        for needle in ("sc.exe", "'delete'", "Remove-Item -LiteralPath $DataDir", "no service registry key left"):
            self.assertIn(needle, S)


if __name__ == "__main__":
    unittest.main()
