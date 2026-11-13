"""Offline guard for the T-0833 tooling: the driver and its WinRM helper compile, the driver holds the dc1 lock,
restores dc1 and reports a before/after snapshot, and the Go stub is proven by `go test ./lab/windows/enrol-stub`."""
import os, py_compile, subprocess, tempfile, unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DRIVER = os.path.join(REPO, "lab", "windows", "bin", "agent-unenrolled-verify")
LIB = os.path.join(REPO, "lab", "windows", "lib", "dc1winrm.py")


class AgentUnenrolledTooling(unittest.TestCase):
    def test_python_compiles(self):
        with tempfile.TemporaryDirectory() as d:
            for f in (DRIVER, LIB):
                py_compile.compile(f, cfile=os.path.join(d, "x.pyc"), doraise=True)

    def test_driver_contract(self):
        src = open(DRIVER).read()
        self.assertIn("with-dc1-lock", src, "must re-exec under the dc1 lock")
        self.assertIn("RESET", src)
        self.assertIn("dc1 BEFORE", src)
        self.assertIn("dc1 AFTER", src)
        self.assertIn("fixture-detects", src, "each check needs a failing fixture")
        self.assertNotIn("WIN_LAB_ADMIN_PASSWORD}", src, "the password must not be formatted into any string")

    def test_stub_proof_runs(self):
        r = subprocess.run(["go", "test", "-count=1", "./lab/windows/enrol-stub"], cwd=REPO, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
