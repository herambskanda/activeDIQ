"""Offline proof for T-0765's DC evidence checks: each judge fails on the bad shape and passes on the good one.
No Windows, no WinRM: the PowerShell output is a literal."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import dc1evidence as ev

SID = "S-1-5-21-1-2-3"
def groups(hit=()):
    rows = [("Domain Admins", SID + "-512"), ("Schema Admins", SID + "-518"), ("Enterprise Admins", SID + "-519"), ("Administrators", "S-1-5-32-544")]
    body = "\n".join(f"PRIV|{n}|{s}|{1 if n in hit else 0}" for n, s in rows)
    return "USER|CN=svc-activediq,OU=ServiceAccounts,DC=win|enabled=True\nMEMBEROF|CN=LabSvc,OU=G,DC=win\n" + body + "\nDONE\n"


class Events(unittest.TestCase):
    def test_each_judged_event_fails(self):
        for i in ev.FAIL_EVENT_IDS:
            bad = ev.event_problems(ev.parse_events(f"EVT|{i}|2026-11-03T06:00:00.0000000Z\nDONE\n"))
            self.assertEqual(len(bad), 1, i)
            self.assertIn(str(i), bad[0])

    def test_clean_window_passes_and_info_events_are_not_judged(self):
        self.assertEqual(ev.event_problems(ev.parse_events("DONE\n")), [])
        self.assertEqual(ev.event_problems(ev.parse_events("EVT|2889|2026-11-03T06:00:00Z\nDONE\n")), [])

    def test_truncated_answer_is_not_read_as_no_events(self):
        with self.assertRaises(ValueError):
            ev.parse_events("EVT|1|x\n")
        with self.assertRaises(ValueError):
            ev.parse_events("")

    def test_since_is_validated_before_it_reaches_powershell(self):
        for bad in ("", "2026-11-03", "x'; Stop-Computer; '", "2026-11-03T06:00:00+01:00"):
            with self.assertRaises(ValueError):
                ev.events_ps(bad)
        self.assertIn("2026-11-03T06:00:00.123Z", ev.events_ps("2026-11-03T06:00:00.123Z"))


class Groups(unittest.TestCase):
    def test_membership_of_each_privileged_group_fails(self):
        for g in ("Domain Admins", "Schema Admins", "Enterprise Admins", "Administrators"):
            _, priv = ev.parse_groups(groups({g}))
            self.assertEqual(len(ev.group_problems(priv)), 1, g)

    def test_no_privileged_membership_passes(self):
        member_of, priv = ev.parse_groups(groups())
        self.assertEqual(ev.group_problems(priv), [])
        self.assertEqual(member_of, ["CN=LabSvc,OU=G,DC=win"])

    def test_missing_rows_or_marker_is_an_error_not_a_pass(self):
        with self.assertRaises(ValueError):
            ev.parse_groups(groups().replace("DONE\n", ""))
        with self.assertRaises(ValueError):
            ev.parse_groups("USER|x|enabled=True\nDONE\n")


if __name__ == "__main__":
    unittest.main()
