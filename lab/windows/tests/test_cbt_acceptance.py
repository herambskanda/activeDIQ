"""Offline proof for T-0148: `gssapi-lab accept` passes only when the correct binds pass AND dc1's Directory Service log holds none
of 2887/3039/3074/3075 in their window AND the wrong-binding control makes 3039 appear. No Windows, no WinRM, no network: the DC
is a fake `ps` that holds a list of events and honours the query window, `go test` is a fake that returns canned output.

Each rule has its failing counterpart, so a mutation of the judge (ignore an id, ignore the window, accept a skip) turns a test red.
Run: python3 -m unittest lab/windows/tests/test_cbt_acceptance.py   (make lab-test-windows-unit)
"""
import datetime as dt, re, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from test_dc1_policy import load_gssapi_lab  # noqa: E402

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB / "lib"))
import cbtevents  # noqa: E402

T0 = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)  # dc1 is in step with this host (T-0850); the log is relative to it


class FakeDC:
    """dc1: a clock that advances 1 s per call to UtcNow, a policy, and a Directory Service log of (id, utc time)."""

    def __init__(self, log=(), integrity=2, cbt=2, control_event=True):
        self.now, self.log, self.integrity, self.cbt = T0, list(log), integrity, cbt
        self.control_event = control_event
        self.wrong_binding_ran_at = None
        self.sent = []

    def ps(self, script):
        self.sent.append(script)
        if "UtcNow" in script:
            self.now += dt.timedelta(seconds=1)
            return 0, self.now.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        if "GPO_LDAPServerIntegrity" in script:
            return 0, "GPO_LDAPServerIntegrity = 4,2"
        if "GetValue" in script and "LDAPServerIntegrity" in script:
            return 0, f"LDAPServerIntegrity = {self.integrity}\nLdapEnforceChannelBindingTokens = {self.cbt}"
        if "Get-WinEvent" in script:
            s, e = [dt.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
                    for x in re.findall(r"Parse\('([^']+)'", script)]
            ids = {int(i) for i in re.search(r"Id=([\d,]+)", script).group(1).split(",")}
            return 0, "\n".join(f"{i}|{t.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')}|The following client ... (fake)"
                                for i, t in self.log if s <= t <= e and i in ids)
        if "Get-ItemProperty" in script:
            return 0, "0"
        return 0, ""


GOOD = "".join(f"=== RUN   {n}\n--- PASS: {n} (0.01s)\n" for n in
               ["TestWindowsLabKerberosKeytabBindWithChannelBinding", "TestWindowsLabKerberosGMSAKeytabBind",
                "TestWindowsLabKerberosOpenKeytabBind", "TestWindowsLabKerberosOpenGMSABind"]) + "PASS\n"
CONTROL_OK = "=== RUN   TestWindowsLabKerberosWrongChannelBindingRejected\n--- PASS: TestWindowsLabKerberosWrongChannelBindingRejected (0.04s)\nPASS\n"


def run_accept(dc, correct_output=GOOD, control_output=CONTROL_OK, correct_rc=0, extra_log_in_correct_window=()):
    with tempfile.TemporaryDirectory() as d:
        m = load_gssapi_lab(d)
        m.ps = dc.ps
        m.time = type("T", (), {"sleep": staticmethod(lambda s: None)})
        calls = []

        def fake_go_test(names, genv):
            calls.append(names)
            if names == m.CONTROL:
                # the wrong binding is logged by the DC "now" (after the correct binds, as in the lab)
                if dc.control_event:
                    dc.log.append((3039, dc.now + dt.timedelta(seconds=1)))
                return 0, control_output
            for i in extra_log_in_correct_window:  # an event the correct binds caused
                dc.log.append((i, dc.now))
            return correct_rc, correct_output

        m.go_test = fake_go_test
        return m.accept(), calls


class Accept(unittest.TestCase):
    def test_passes_when_binds_pass_log_is_clean_and_control_logs_3039(self):
        fails, calls = run_accept(FakeDC())
        self.assertEqual(fails, [])
        self.assertEqual(len(calls), 2, "correct binds then control")

    def test_each_named_event_in_the_window_fails_the_acceptance(self):
        for ev in (2887, 3039, 3074, 3075):  # spelled out: the test must not follow a mutated constant
            with self.subTest(event=ev):
                fails, _ = run_accept(FakeDC(), extra_log_in_correct_window=(ev,))
                self.assertTrue(any(f"event {ev} " in f for f in fails), fails)

    def test_context_events_are_reported_not_judged(self):
        fails, _ = run_accept(FakeDC(), extra_log_in_correct_window=(2889,))
        self.assertEqual(fails, [])

    def test_events_outside_the_window_do_not_count(self):
        # 3039 an hour before the run (an earlier session's wrong-binding test) must not fail a clean run
        fails, _ = run_accept(FakeDC(log=[(3039, T0 - dt.timedelta(hours=1)), (2887, T0 - dt.timedelta(days=1))]))
        self.assertEqual(fails, [])

    def test_control_without_3039_fails_because_an_empty_log_would_prove_nothing(self):
        fails, _ = run_accept(FakeDC(control_event=False))
        self.assertTrue(any("control" in f and "3039" in f for f in fails), fails)

    def test_a_failed_bind_fails_the_acceptance(self):
        broken = GOOD.replace("--- PASS: TestWindowsLabKerberosOpenGMSABind", "--- FAIL: TestWindowsLabKerberosOpenGMSABind")
        fails, _ = run_accept(FakeDC(), correct_output=broken, correct_rc=1)
        self.assertTrue(any("did not all succeed" in f for f in fails), fails)

    def test_a_skipped_bind_is_not_a_pass(self):
        skipped = GOOD.replace("--- PASS: TestWindowsLabKerberosOpenKeytabBind", "--- SKIP: TestWindowsLabKerberosOpenKeytabBind")
        fails, _ = run_accept(FakeDC(), correct_output=skipped, correct_rc=0)
        self.assertTrue(any("did not all succeed" in f for f in fails), fails)

    def test_a_bind_missing_from_the_output_is_not_a_pass(self):
        fails, _ = run_accept(FakeDC(), correct_output="PASS\n")
        self.assertTrue(fails)

    def test_policy_not_enforced_stops_before_any_bind(self):
        for kw in ({"integrity": 1}, {"cbt": 1}):
            with self.subTest(kw=kw), self.assertRaises(SystemExit) as cm:
                run_accept(FakeDC(**kw))
            self.assertIn("not enforcing", str(cm.exception.code))

    def test_policy_drifting_during_the_run_fails(self):
        class Drift(FakeDC):
            def ps(self, script):
                r = super().ps(script)
                if "Set-ItemProperty" in script and "Diagnostics" in script and "-Value 2" in script:
                    self.integrity = 1
                return r
        fails, _ = run_accept(Drift())
        self.assertTrue(any("LDAPServerIntegrity" in f for f in fails), fails)

    def test_diagnostics_value_is_restored(self):
        dc = FakeDC()
        run_accept(dc)
        sets = [s for s in dc.sent if "Set-ItemProperty" in s]
        self.assertEqual(len(sets), 2)
        self.assertIn("-Value 2", sets[0])
        self.assertIn("-Value 0", sets[1])


class Pure(unittest.TestCase):
    def test_query_is_built_from_typed_values_only(self):
        t = dt.datetime(2026, 11, 2, 10, 0, 0, tzinfo=dt.timezone.utc)
        q = cbtevents.events_ps(t, t + dt.timedelta(seconds=5))
        self.assertIn("2026-11-02T10:00:00.000Z", q)
        self.assertIn("Id=2886,2887,2888,2889,3039,3040,3041,3074,3075", q)
        with self.assertRaises(ValueError):
            cbtevents.events_ps(T0.replace(tzinfo=None), T0)
        with self.assertRaises(ValueError):
            cbtevents.events_ps(T0, T0, ids=["3039; Remove-Item C:\\"])

    def test_parse_ignores_noise(self):
        out = "#< CLIXML\n3039|2026-11-02T10:00:01.123Z|failed the channel binding\nnot an event\n"
        self.assertEqual(cbtevents.parse(out), [(3039, "2026-11-02T10:00:01.123Z", "failed the channel binding")])

    def test_the_four_named_events(self):
        self.assertEqual(cbtevents.MUST_BE_ABSENT, (2887, 3039, 3074, 3075))
        self.assertEqual(sorted(set(cbtevents.QUERY_IDS) & {2887, 3039, 3074, 3075}), [2887, 3039, 3074, 3075])


if __name__ == "__main__":
    unittest.main()
