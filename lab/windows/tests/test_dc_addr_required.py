"""T-1279: the Windows lab drivers have no default DC address.

A driver started without WIN_LAB_DC_ADDR must exit non-zero naming the key, before it takes the dc1 lock,
builds anything or opens a socket (a sitecustomize hook turns any connect into a recorded failure), and no
file under lab/ or the runbooks may hard-code the old dc1 address that now belongs to another LAN device.
"""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
REPO = LAB.parent.parent
OLD = "192.168.1." + "9"  # assembled so this file does not match its own scan
DRIVERS = ["agent-verify", "agent-unenrolled-verify", "gssapi-lab", "dc1-clock", "dc1-policy", "dc1-evidence"]
HOOK = """import socket
def _no(*a, **k):
    open(%r, "a").write("connect\\n"); raise OSError("network blocked by test")
socket.socket.connect = _no
socket.socket.connect_ex = _no
socket.create_connection = _no
"""


class DcAddrRequired(unittest.TestCase):
    def run_driver(self, name, env_text, extra_env=None):
        d = Path(tempfile.mkdtemp())
        marker = d / "net.log"
        (d / "sitecustomize.py").write_text(HOOK % str(marker))
        envf = d / "lab.env"
        envf.write_text(env_text); envf.chmod(0o600)
        env = {k: v for k, v in os.environ.items() if k != "WIN_LAB_DC_ADDR"}
        env.update(WIN_LAB_ENV=str(envf), PYTHONPATH=str(d), DIQ_DC1_LOCK_DIR=str(d / "lock"))
        env.update(extra_env or {})
        if name == "dc1-evidence":
            args = ["now"]
        elif name == "agent-unenrolled-verify":
            args = ["--log", str(d / "x.log")]  # no subcommand; the address gate runs right after parse_args
        else:
            args = ["--log", str(d / "x.log"), "prepare"]
        r = subprocess.run([sys.executable, str(LAB / "bin" / name), *args],
                           env=env, capture_output=True, text=True, timeout=60)
        return r, marker, d

    def test_missing_key_is_a_hard_error_before_any_connection(self):
        for name in DRIVERS:
            if not (LAB / "bin" / name).exists():
                continue  # agent-unenrolled-verify lands with T-1249; test_every_driver_is_covered guards it
            with self.subTest(driver=name):
                r, marker, d = self.run_driver(name, "WIN_LAB_ADMIN_PASSWORD=not-a-real-secret\n")
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("WIN_LAB_DC_ADDR", r.stderr)
                self.assertNotIn("not-a-real-secret", r.stderr + r.stdout)
                self.assertFalse(marker.exists(), "driver opened a connection")
                self.assertNotIn("lock held", r.stderr)  # failed before the dc1 lock
                self.assertFalse((d / "lock").exists())

    def test_empty_and_malformed_values_are_rejected(self):
        for name in DRIVERS:
            if not (LAB / "bin" / name).exists():
                continue
            for bad in ("", "1.2.3.4;rm -rf"):
                with self.subTest(driver=name, value=bad):
                    r, marker, _ = self.run_driver(name, f"WIN_LAB_DC_ADDR={bad}\nWIN_LAB_ADMIN_PASSWORD=x\n")
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn("WIN_LAB_DC_ADDR", r.stderr)
                    self.assertFalse(marker.exists())

    def test_set_key_passes_the_address_gate(self):
        from importlib.machinery import SourceFileLoader
        sys.path.insert(0, str(LAB / "lib"))
        import labaddr
        d = Path(tempfile.mkdtemp()); f = d / "e"; f.write_text('WIN_LAB_DC_ADDR="10.9.8.7"\n')
        self.assertEqual(labaddr.require_dc_addr("t", str(REPO), {"WIN_LAB_ENV": str(f)}), "10.9.8.7")
        self.assertEqual(labaddr.require_dc_addr("t", str(REPO), {"WIN_LAB_ENV": str(f), "WIN_LAB_DC_ADDR": "dc1.x"}), "dc1.x")

    def test_every_driver_is_covered(self):
        # any driver under bin/ that talks WinRM must use the gate, so a new driver cannot reintroduce a default
        for p in sorted(q for q in (LAB / "bin").iterdir() if q.is_file()):
            t = p.read_text(errors="replace")
            if "winrm" in t or "dc1winrm" in t:
                # dc1winrm.load_env returns require_dc_addr(...), so a driver that loads its env through it is gated
                self.assertTrue("require_dc_addr" in t or "dc1winrm.load_env" in t,
                                f"{p.name} reaches the DC without the required-address gate")
                self.assertIn(p.name, DRIVERS, f"add {p.name} to DRIVERS")

    def test_old_address_is_gone_from_lab_and_runbooks(self):
        hits = []
        roots = [LAB.parent] + [p for p in (REPO / "knowledge/development/runbooks").glob("*") if p.is_file()]
        for root in roots:
            for p in ([root] if root.is_file() else root.rglob("*")):
                if p.is_file() and ".win-lab" not in p.name and "__pycache__" not in p.parts:
                    try:
                        if OLD in p.read_text():
                            hits.append(str(p.relative_to(REPO)))
                    except UnicodeDecodeError:
                        pass
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
