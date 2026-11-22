"""T-1267 security fix: `gssapi-lab keytab` must not put the svc password into PowerShell script text (CLAUDE.md rule 5).
The script is constant; the password reaches dc1 only through the WinRM shell environment (env_vars)."""
import base64, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dc1_policy import FakeDC, load_gssapi_lab

NASTY = "Wl-x\u2019; calc; \u2018'\"`$(x)\u201a\u201b"


class KeytabSecretChannel(unittest.TestCase):
    def test_password_only_in_env_vars(self):
        with tempfile.TemporaryDirectory() as d:
            m = load_gssapi_lab(d)
            m.env["WIN_LAB_SVC_PASSWORD"] = NASTY
            dc, calls = FakeDC(), []

            def ps(script, env_vars=None):
                calls.append((script, env_vars))
                if "script-exit" in script:
                    return 0, "script-exit True"
                if "ToBase64String" in script:
                    return 0, base64.b64encode(b"kt").decode()
                return dc.ps(script)

            m.ps, m.put, m.OUT = ps, lambda *a: None, d
            m.keytab()
            for script, ev in calls:
                self.assertNotIn(NASTY, script)
                for ch in "\u2019\u2018\u201a\u201b":
                    self.assertNotIn(ch, script)
                # also not smuggled through the encoded form the transport would send
                self.assertNotIn(NASTY.encode("utf-16le"), base64.b64decode(base64.b64encode(script.encode("utf-16le"))))
            run = [(s, ev) for s, ev in calls if "svc-keytab.ps1" in s and "script-exit" in s]
            self.assertEqual(len(run), 1)
            self.assertEqual(run[0][1], {"SVC_PW": NASTY})
            self.assertEqual(run[0][0], m.KEYTAB_PS)
            self.assertTrue(all(ev is None for s, ev in calls if s is not run[0][0]))


if __name__ == "__main__":
    unittest.main()
