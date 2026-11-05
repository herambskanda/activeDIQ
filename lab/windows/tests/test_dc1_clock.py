"""Offline proof for T-0850: `dc1-clock check` and `dc1-clock fix` against a fake DC (no Windows, no WinRM, no sleeping).

Each good path has a failing counterpart, so the check is shown to catch a skewed dc1 and a `fix` that crashes.
"""
import datetime, importlib.machinery, importlib.util, io, os, sys, tempfile, time, unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB / "lib"))


def load_clock(env_dir):
    envf = Path(env_dir) / ".win-lab.env"
    envf.write_text('WIN_LAB_ADMIN_PASSWORD="x"\nWIN_LAB_DC_ADDR="192.0.2.1"\n')
    os.environ["WIN_LAB_ENV"] = str(envf)
    loader = importlib.machinery.SourceFileLoader("dc1_clock_under_test", str(LAB / "bin" / "dc1-clock"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class FakeDC:
    """Answers [DateTime]::UtcNow with host time + offset; records every script. `fix` (the w32tm /config call) moves the offset to 0."""

    def __init__(self, offset=datetime.timedelta(0), drop_session=False):
        self.offset, self.sent, self.drop_session = offset, [], drop_session

    def ps(self, script):
        self.sent.append(script)
        if "UtcNow" in script:
            t = datetime.datetime.now(datetime.timezone.utc) + self.offset
            return 0, t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        if "manualpeerlist" in script:
            self.offset = datetime.timedelta(0)
            if self.drop_session:
                raise ConnectionError("session cut by clock step")
            return 0, ""
        if "w32tm /query" in script:
            return 0, "Source: 162.159.200.1,0x8\nStratum: 4"
        return 0, ""


class DC1Clock(unittest.TestCase):
    def run_cli(self, dc, argv):
        """-> (exit code, stdout, stderr). Never sleeps."""
        with tempfile.TemporaryDirectory() as d:
            m = load_clock(d)
            m._ps = dc.ps
            old = sys.argv
            sys.argv = ["dc1-clock"] + argv
            out, err = io.StringIO(), io.StringIO()
            try:
                # patch the real time.sleep, not the module's name for it: a missing `import time` must still fail
                with redirect_stdout(out), redirect_stderr(err), mock.patch.object(time, "sleep", lambda s: None):
                    try:
                        code = m.check(float(argv[2])) if argv[:2] == ["check", "--max-skew"] else \
                            m.check(1.0) if argv == ["check"] else m.fix()
                    except SystemExit as e:
                        code = e.code
            finally:
                sys.argv = old
            return code, out.getvalue(), err.getvalue()

    def test_check_passes_when_dc1_is_in_step(self):
        code, out, _ = self.run_cli(FakeDC(), ["check"])
        self.assertEqual(code, 0)
        self.assertIn("dc1-clock: OK", out)
        self.assertIn("162.159.200.1", out)

    def test_check_fails_for_the_12h30m_skew_of_the_ticket(self):
        code, out, err = self.run_cli(FakeDC(datetime.timedelta(hours=12, minutes=30)), ["check"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)
        self.assertIn("45000", out)

    def test_check_strict_limit_fails_a_small_skew(self):
        code, _, _ = self.run_cli(FakeDC(datetime.timedelta(seconds=0.5)), ["check", "--max-skew", "0.0001"])
        self.assertEqual(code, 1)

    def test_fix_runs_to_the_after_line_and_exits_0(self):
        dc = FakeDC(datetime.timedelta(hours=12, minutes=30))
        code, out, _ = self.run_cli(dc, ["fix"])
        self.assertEqual(code, 0, out)
        self.assertIn("before: dc1 minus host = 45000", out)
        self.assertRegex(out, r"after: dc1 minus host = -?0\.\d{3} s")
        sent = [s for s in dc.sent if "manualpeerlist" in s]
        self.assertEqual(len(sent), 1)
        self.assertIn("162.159.200.1,0x8", sent[0])
        self.assertFalse([s for s in dc.sent if "Set-Date" in s], "fix must use w32time, not a hand-set clock")

    def test_fix_survives_the_session_being_cut_by_the_clock_step(self):
        code, out, _ = self.run_cli(FakeDC(datetime.timedelta(hours=12, minutes=30), drop_session=True), ["fix"])
        self.assertEqual(code, 0, out)
        self.assertIn("session dropped", out)
        self.assertIn("after:", out)

    def test_fix_exits_1_when_clock_stays_wrong(self):
        class Stuck(FakeDC):
            def ps(self, script):
                r = super().ps(script)
                self.offset = datetime.timedelta(hours=12, minutes=30)
                return r
        code, out, _ = self.run_cli(Stuck(datetime.timedelta(hours=12)), ["fix"])
        self.assertEqual(code, 1)
        self.assertIn("after:", out)


if __name__ == "__main__":
    unittest.main()
