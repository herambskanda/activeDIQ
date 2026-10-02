"""Unit tests for the lab seed generator (no Docker needed). Run: make lab-test-unit

Each test states the violation it catches; `make lab-test-unit` fails if the generator regresses.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "seed"))
import generate  # noqa: E402

NOW = 1790000000 - 1790000000 % 86400
PW = ("seed-test-user-pw", "seed-test-svc-pw")


def gen(tier="small", seed=1, now=NOW):
    return generate.generate(tier, seed, now, *PW)


class Determinism(unittest.TestCase):
    def test_same_inputs_are_byte_identical(self):
        a, ma = gen()
        b, mb = gen()
        self.assertEqual(a, b)
        self.assertEqual(ma, mb)

    def test_different_seed_differs(self):
        a, _ = gen(seed=1)
        b, _ = gen(seed=2)
        self.assertNotEqual(a["loadplan.txt"] + "".join(v for k, v in a.items() if k.startswith("10-")),
                            b["loadplan.txt"] + "".join(v for k, v in b.items() if k.startswith("10-")))
        self.assertNotEqual(a["31-members.ldif"], b["31-members.ldif"])

    def test_cli_writes_files_and_requires_passwords(self):
        with tempfile.TemporaryDirectory() as d:
            import os
            env = {k: v for k, v in os.environ.items() if not k.startswith("LAB_")}
            old = dict(os.environ)
            os.environ.clear(); os.environ.update(env)
            try:
                self.assertEqual(generate.main(["--tier", "small", "--out", d]), 2)  # no passwords => refuse
                os.environ.update(LAB_USER_PASSWORD="a", LAB_SVC_PASSWORD="b")
                self.assertEqual(generate.main(["--tier", "small", "--out", d, "--now", str(NOW)]), 0)
            finally:
                os.environ.clear(); os.environ.update(old)
            self.assertTrue((Path(d) / "loadplan.txt").exists())
            self.assertTrue((Path(d) / "manifest.json").exists())


class Shape(unittest.TestCase):
    def test_tier_sizes(self):
        _, m = gen("small")
        self.assertEqual(m["counts"]["generated_users"], 300)
        _, m = gen("standard")
        self.assertEqual(m["counts"]["generated_users"], 5000)
        self.assertEqual(m["counts"]["big_group_members"], 3000)   # > 1500 forces ranged retrieval
        self.assertGreaterEqual(m["counts"]["computers"], 1500)
        self.assertGreaterEqual(m["counts"]["departments"], 10)

    def test_every_user_state_present(self):
        _, m = gen("small")
        states = m["counts"]["user_states"]
        for s in ["disabled", "stale", "expired_account", "expiring_soon", "never_expires",
                  "must_change", "pwd_expired", "pwd_expiring", "never_logged_on", "normal"]:
            self.assertGreaterEqual(states.get(s, 0), 2, s)

    def test_manifest_matches_ldif(self):
        """The live check asserts the directory against the manifest, so the manifest must match the LDIF."""
        files, m = gen("small")
        body = "".join(v for k, v in files.items() if k.startswith("10-"))
        for state, want in m["counts"]["user_states"].items():
            self.assertEqual(body.count(f"description: lab user state={state}\n"), want, state)
        for state, lst in m["samples"].items():
            self.assertTrue(lst and all("sam" in x for x in lst), state)

    def test_edge_cases_present(self):
        files, m = gen("small")
        text = files["01-objects.ldif"]
        self.assertIn("CN=Smith\\, John,", text)          # comma escaped in the DN
        self.assertIn("CN=\\#Hash Lead,", text)          # leading # escaped
        self.assertIn("CN=Plus\\+Sign,", text)
        self.assertIn('\\"Q\\"', text)                     # quotes
        self.assertTrue(any(len(e["cn"]) == 64 for e in m["edge_users"]))
        self.assertTrue(any(len(e["sam"]) == 20 for e in m["edge_users"]))
        self.assertTrue(any(ord(c) > 0xFFFF for e in m["edge_users"] for c in e["cn"]))   # non-BMP
        self.assertTrue(any("́" in e["cn"] for e in m["edge_users"]))                # NFD

    def test_cycle_and_nesting_groups(self):
        files, _ = gen("small")
        members = files["31-members.ldif"]
        for a, b in [("A", "B"), ("B", "C"), ("C", "A")]:
            self.assertRegex(members, r"dn: CN=GG-Cycle-%s,[^\n]*\nchangetype: modify\nadd: member\nmember: CN=GG-Cycle-%s," % (a, b))

    def test_no_real_or_partner_names_and_synthetic_mail(self):
        files, _ = gen("small")
        blob = "\n".join(files.values())
        for line in blob.splitlines():
            if line.startswith("mail:"):
                self.assertTrue(line.endswith("@example.com"), line)
        # partner/customer names live only in knowledge/business/partnerships/ — never in fixtures
        repo = Path(__file__).resolve().parents[2]
        partner_dir = repo / "knowledge" / "business" / "partnerships"
        if partner_dir.exists():
            import re
            for f in partner_dir.glob("*.md"):
                for m in re.finditer(r"^#+\s+(?:Partner|Customer):\s*(.+)$", f.read_text(), re.M):
                    self.assertNotIn(m.group(1).strip().lower(), blob.lower())

    def test_unique_names_and_sam_account_names(self):
        files, _ = gen("standard")
        sams = [l for l in files["01-objects.ldif"].splitlines() if l.startswith("sAMAccountName: ")]
        self.assertEqual(len(sams), len(set(sams)))
        self.assertTrue(all(len(l.split(": ", 1)[1]) <= 20 for l in sams if not l.endswith("$")))


class PasswordAges(unittest.TestCase):
    def test_load_plan_orders_ous_first_and_groups_after_users(self):
        files, _ = gen("small")
        plan = files["loadplan.txt"].splitlines()
        self.assertTrue(plan[0].endswith("01-objects.ldif"))
        self.assertTrue(plan[-3].endswith("20-groups.ldif"))
        self.assertTrue(plan[-1].endswith("31-members.ldif"))

    def test_must_change_is_the_only_explicit_pwdlastset(self):
        """Samba rejects pwdLastSet other than 0/-1; the generator must never emit another value."""
        files, _ = gen("standard")
        for name, body in files.items():
            for line in body.splitlines():
                if line.startswith("pwdLastSet:"):
                    self.assertEqual(line, "pwdLastSet: 0", name)

    def test_aged_buckets_get_a_past_clock(self):
        files, _ = gen("small")
        epochs = [int(l.split()[0]) for l in files["loadplan.txt"].splitlines() if "aged" in l and not l.split()[2].startswith("10-aged-0000")]
        self.assertTrue(epochs and all(e < NOW for e in epochs))


class Escaping(unittest.TestCase):
    def test_esc_dn(self):
        self.assertEqual(generate.esc_dn("a,b"), "a\\,b")
        self.assertEqual(generate.esc_dn("#x"), "\\#x")
        self.assertEqual(generate.esc_dn(" x"), "\\ x")
        self.assertEqual(generate.esc_dn("x "), "x\\ ")
        self.assertEqual(generate.esc_dn('a"b+c<d>e;f=g\\h'), r'a\"b\+c\<d\>e\;f\=g\\h')
        self.assertEqual(generate.esc_dn("a#b"), "a#b")

    def test_ldif_base64_for_unsafe_values(self):
        self.assertEqual(generate.ldif_value("cn", "plain"), "cn: plain")
        self.assertTrue(generate.ldif_value("cn", " lead").startswith("cn:: "))
        self.assertTrue(generate.ldif_value("cn", "trail ").startswith("cn:: "))
        self.assertTrue(generate.ldif_value("cn", "ü").startswith("cn:: "))
        self.assertTrue(generate.ldif_value("cn", ":x").startswith("cn:: "))


if __name__ == "__main__":
    unittest.main()
