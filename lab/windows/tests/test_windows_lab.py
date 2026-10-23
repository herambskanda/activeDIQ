"""Offline proof of the Windows lab controller (T-0254): runs the real bin/windows-lab against stub
virsh/virt-install/qemu-img/xorriso/nc/curl and checks the contract: one command builds both VMs, a clean
snapshot is taken, reset reverts it, credentials are random/0600/never in argv, logs or the tracked template."""
import json, os, re, stat, subprocess, tempfile, unittest
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
CTL = LAB / "bin/windows-lab"
STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "$STUB_LOG"
case "$(basename "$0")" in
  xorriso) # last arg is the source dir; keep a copy so the test can inspect the config CD contents
    for a; do src="$a"; done; out=""; prev=""
    for a; do [ "$prev" = -o ] && out="$a"; prev="$a"; done
    cp -r "$src" "$out.dir"; : > "$out";;
  virsh) case "$*" in *domstate*) echo "shut off";; *net-info*|*dominfo*) exit 1;; esac;;
  curl) for a; do p="$a"; done; : > "$p"; for a; do [ "$prev" = -o ] && : > "$a"; prev="$a"; done;;
  openssl) echo stub;;
esac
exit 0
"""


class WindowsLab(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        b = self.d / "bin"; b.mkdir()
        for n in ("virsh", "virt-install", "qemu-img", "xorriso", "curl", "nc"):
            (b / n).write_text(STUB); (b / n).chmod(0o755)
        self.log = self.d / "stub.log"; self.log.write_text("")
        self.env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", STUB_LOG=str(self.log), WIN_LAB_STATE=str(self.d / "st"),
                        WIN_LAB_ENV=str(self.d / "w.env"), WIN_LAB_CA=str(self.d / "ca.pem"), WIN_LAB_LOGDIR=str(self.d / "logs"),
                        WIN_LAB_WAIT_SECS="1", WIN_LAB_DRYRUN="")
        (self.d / "st").mkdir()
        (self.d / "st/ws2025-eval.iso").write_text("iso")  # pretend the ISO is already downloaded

    def ctl(self, *a, **kw):
        env = dict(self.env, **kw)
        return subprocess.run([str(CTL), *a], env=env, capture_output=True, text=True, timeout=60)

    def stubbed_up(self):
        # openssl s_client is not stubbed: pre-seed the CA export by making export_ca succeed through a fake CA
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(self.d / "k"), "-out", str(self.d / "ca.pem"),
                        "-subj", "/CN=stub", "-days", "1"], capture_output=True, check=True)
        return self.ctl("up", WIN_LAB_SKIP_CA="1")

    def test_up_builds_both_vms_snapshots_and_keeps_secrets_out_of_argv(self):
        r = self.stubbed_up()
        log = self.log.read_text()
        if r.returncode != 0 and "could not read the lab root CA" not in r.stderr:
            self.fail(r.stdout + r.stderr)
        self.assertEqual(log.count("virt-install"), 2)
        self.assertIn("diq-win-dc1", log); self.assertIn("diq-win-fs1", log)
        self.assertRegex(log, r"snapshot-create-as diq-win-dc1 clean")
        self.assertRegex(log, r"snapshot-create-as diq-win-fs1 clean")
        self.assertLess(log.index("name diq-win-dc1"), log.index("name diq-win-fs1"))  # DC first
        env = self.d / "w.env"
        self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
        pws = re.findall(r"=(Wl-[0-9a-f]{28}-aA1!)", env.read_text())
        self.assertEqual(len(set(pws)), 4)
        for pw in pws:
            self.assertNotIn(pw, log); self.assertNotIn(pw, r.stdout + r.stderr)

    def test_config_cd_holds_secrets_only_in_state_template_holds_none(self):
        self.stubbed_up()
        cfg = self.d / "st/cfg-diq-win-dc1.iso.dir"
        lab = json.loads((cfg / "lab.json").read_text())
        self.assertEqual(lab["role"], "dc"); self.assertEqual(lab["domain"], "win.activediq.test")
        x = (cfg / "autounattend.xml").read_text()
        self.assertIn(lab["adminPassword"].replace("&", "&amp;"), x); self.assertIn("<ComputerName>DC1</ComputerName>", x)
        self.assertNotIn("@@", x)
        tmpl = (LAB / "guest/autounattend.xml.tmpl").read_text()
        self.assertIn("@@ADMINPW@@", tmpl)
        for f in (LAB / "guest").iterdir():
            self.assertIsNone(re.search(r"Wl-[0-9a-f]{20}", f.read_text()), f.name)

    def test_reset_reverts_both_to_clean_snapshot(self):
        self.stubbed_up(); self.log.write_text("")
        r = self.ctl("reset")
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log.read_text()
        self.assertIn("snapshot-revert diq-win-dc1 clean", log); self.assertIn("snapshot-revert diq-win-fs1 clean", log)

    def test_destroy_removes_credentials_but_keeps_iso(self):
        self.stubbed_up()
        self.assertEqual(self.ctl("destroy").returncode, 0)
        self.assertFalse((self.d / "w.env").exists()); self.assertTrue((self.d / "st/ws2025-eval.iso").exists())

    def test_iso_checksum_mismatch_fails(self):
        (self.d / "st/ws2025-eval.iso").unlink()
        r = self.ctl("up", WIN_LAB_ISO_SHA256="0" * 64)
        self.assertNotEqual(r.returncode, 0)

    def test_guest_scripts_carry_the_audit_and_ntlm_hooks(self):
        g = (LAB / "guest/audit-gpo.ps1").read_text()
        for needle in ("Credential Validation", "AuditReceivingNTLMTraffic", "RestrictSendingNTLMTraffic", "AuditNTLMInDomain",
                       "Microsoft-Windows-NTLM/Operational", "8001", "8004"):
            self.assertIn(needle, g)

    def test_missing_lab_fails_loudly_for_connector_run(self):
        r = self.ctl("test-connector")
        self.assertNotEqual(r.returncode, 0); self.assertIn("lab not up", r.stderr)

    def test_no_state_or_credentials_tracked(self):
        out = subprocess.run(["git", "ls-files", str(LAB)], capture_output=True, text=True, cwd=LAB).stdout
        self.assertNotRegex(out, r"\.win-lab\.env|\.state/|\.qcow2|\.iso")


if __name__ == "__main__":
    unittest.main()
