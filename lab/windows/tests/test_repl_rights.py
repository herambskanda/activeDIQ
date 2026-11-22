"""Offline proof for the T-1510 judge (lib/replrights.py): each rule fails on the bad shape and passes on the good one.
No Windows, no WinRM: the PowerShell output is a literal. The key rule: an empty answer is never read as a verdict."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import replrights as rr

BASES = ("rootDSE", "domainHead", "configHead", "schemaHead", "ntdsSettings")


def run(admin=0, mon1=0, mon2=0, none=0, restored=True, ou_gone=True, mon_groups="Domain Users", none_error=False, finish=True):
    L = ["SETUP|mon_memberOf|" + mon_groups, "SETUP|none_memberOf|Domain Users"]
    def reads(p, s, n, only=BASES):
        for b in BASES:
            if p == "t1510-none" and none_error:
                L.append(f"READ|{p}|{s}|{b}|error|LdapException:50")
            else:
                L.append(f"READ|{p}|{s}|{b}|entry|sentinel=True|repl_attrs_returned={n if b in only else 0}|")
    reads("administrator", "S0_no_grants", admin, ("rootDSE",))
    reads("t1510-none", "S0_no_grants", none, ("rootDSE",))
    reads("t1510-mon", "S1_right_on_domain_head", mon1, ("rootDSE",))
    reads("t1510-mon", "S2_right_on_all_heads", mon2, ("rootDSE",))
    L += ["DSYNC|objects|live=a|victim=b",
          "DSYNC|svc-activediq|precheck|victim_visible_before_delete=1|polls=2",
          "DSYNC|svc-activediq|delta|entries=1|live_change_seen=1|delete_seen=0|isDeleted=|whenChanged=|origin_time=none|replattrmeta=not_returned",
          "DSYNC|administrator|delta|entries=2|live_change_seen=1|delete_seen=1|isDeleted=TRUE|whenChanged=x|origin_time=none|replattrmeta=not_returned"]
    for h in ("A", "B", "C"):
        L.append(f"CLEAN|dacl_restored|{h}|{restored}")
    L.append(f"CLEAN|ou_gone|{ou_gone}")
    return "\n".join(L) + ("\nDONE\n" if finish else "\n")


def judge(**kw):
    return rr.conclusions(rr.parse(run(**kw)))


class Judge(unittest.TestCase):
    def test_empty_everywhere_is_inconclusive_not_a_verdict(self):
        facts, bad = judge()
        self.assertEqual(bad, [])
        self.assertFalse(facts["conclusive"])
        self.assertIsNone(facts["mon_right_sufficient"])
        self.assertIn("INCONCLUSIVE", facts["location"])

    def test_right_sufficient_when_mon_matches_admin(self):
        facts, bad = judge(admin=2, mon1=2)
        self.assertEqual(bad, [])
        self.assertTrue(facts["conclusive"] and facts["mon_right_sufficient"])
        self.assertEqual(facts["location"], "rootDSE")

    def test_right_insufficient_is_reported_and_wider_heads_noted(self):
        facts, bad = judge(admin=2, mon1=0, mon2=2)
        self.assertFalse(facts["mon_right_sufficient"])
        self.assertTrue(facts["mon_needs_wider_heads"])
        facts, _ = judge(admin=2, mon1=0, mon2=0)
        self.assertFalse(facts["mon_right_sufficient"])
        self.assertFalse(facts["mon_needs_wider_heads"])

    def test_no_right_principal_receiving_values_invalidates_the_premise(self):
        _, bad = judge(admin=2, mon1=2, none=2)
        self.assertTrue(any("no-right principal received" in b for b in bad))

    def test_no_right_read_error_fails(self):
        _, bad = judge(none_error=True)
        self.assertTrue(any("expected an attribute-less entry" in b for b in bad))

    def test_unrestored_acl_or_leftover_ou_fails(self):
        self.assertTrue(any("DACL not restored" in b for b in judge(restored=False)[1]))
        self.assertTrue(any("not removed" in b for b in judge(ou_gone=False)[1]))

    def test_privileged_membership_fails(self):
        for g in ("Domain Admins", "Administrators", "Enterprise Admins"):
            self.assertTrue(any(g in b for b in judge(mon_groups=f"Domain Users, {g}")[1]), g)

    def test_truncated_run_is_not_a_result(self):
        with self.assertRaises(ValueError):
            rr.parse(run(finish=False))

    def test_dirsync_rows_parsed(self):
        facts, _ = judge()
        self.assertEqual(facts["dirsync"]["administrator"]["delete_seen"], "1")
        self.assertEqual(facts["dirsync"]["svc-activediq"]["delete_seen"], "0")
        self.assertEqual(facts["dirsync"]["svc-activediq"]["victim_visible_before_delete"], "1")
        self.assertEqual(facts["dirsync"]["administrator"]["victim_visible_before_delete"], "?")  # no precheck row: unknown, not "yes"


class Script(unittest.TestCase):
    def test_password_goes_in_the_command_not_the_file(self):
        c = rr.run_command("pa'ss")
        self.assertIn("$env:T1510_SVC='pa''ss'", c)
        self.assertIn("Remove-Item", c)
        self.assertNotIn("pa'ss", rr.guest_bytes().decode())
        self.assertIn("$env:T1510_SVC", rr.guest_bytes().decode())
        for bad in ("", None, "a\nb"):
            with self.assertRaises(ValueError):
                rr.run_command(bad)

    def test_guest_script_is_least_privilege(self):
        with open(rr.GUEST_PS, encoding="utf-8") as f:
            s = "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))  # code only, not the header prose
        self.assertIn("DS-Replication-Monitor-Topology", s)  # right read from the forest by name, not hard-coded
        for forbidden in ("Get-Changes", "Domain Admins", "Add-ADGroupMember", "f98340fb"):
            self.assertNotIn(forbidden, s)
        self.assertNotIn("Write-Output $Svc", s)


if __name__ == "__main__":
    unittest.main()
