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
  go) echo "go-env WIN_LAB_DC_ADDR=$WIN_LAB_DC_ADDR WIN_LAB_TLS_NAME=$WIN_LAB_TLS_NAME WIN_LAB_CA=$WIN_LAB_CA WIN_LAB_ENV=$WIN_LAB_ENV" >> "$STUB_LOG";;
esac
exit 0
"""


class WindowsLab(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        b = self.d / "bin"; b.mkdir()
        for n in ("virsh", "virt-install", "qemu-img", "xorriso", "curl", "nc", "go"):
            (b / n).write_text(STUB); (b / n).chmod(0o755)
        self.log = self.d / "stub.log"; self.log.write_text("")
        self.env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", STUB_LOG=str(self.log), WIN_LAB_STATE=str(self.d / "st"),
                        WIN_LAB_ENV=str(self.d / "w.env"), WIN_LAB_CA=str(self.d / "ca.pem"), WIN_LAB_LOGDIR=str(self.d / "logs"),
                        WIN_LAB_WAIT_SECS="1", WIN_LAB_DRYRUN="", WIN_LAB_MODE="local")
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


SECRET = "Wl-" + "ab" * 14 + "-aA1!"


class ExternalMode(unittest.TestCase):
    """T-0428: WIN_LAB_MODE=external targets an operator-provided DC (Proxmox VM 112): no virsh, LDAPS verified."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        b = self.d / "bin"; b.mkdir()
        for n in ("virsh", "virt-install", "qemu-img", "xorriso", "curl", "nc", "go"):
            (b / n).write_text(STUB); (b / n).chmod(0o755)
        self.log = self.d / "stub.log"; self.log.write_text("")
        self.envf = self.d / "ext.env"; self.envf.write_text(f"WIN_LAB_SVC_PASSWORD={SECRET}\n"); self.envf.chmod(0o600)
        self.ca = self.d / "ca.pem"; self.ca.write_text("pem")
        self.base = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", STUB_LOG=str(self.log), WIN_LAB_MODE="external",
                         WIN_LAB_DC_ADDR="10.9.8.7", WIN_LAB_TLS_NAME="dc1.win.activediq.test", WIN_LAB_CA=str(self.ca),
                         WIN_LAB_ENV=str(self.envf), WIN_LAB_LOGDIR=str(self.d / "logs"), WIN_LAB_STATE=str(self.d / "st"))

    def ctl(self, *a, **kw):
        return subprocess.run([str(CTL), *a], env=dict(self.base, **kw), capture_output=True, text=True, timeout=60)

    def test_connector_run_targets_external_host_without_virsh_and_without_secrets_in_argv(self):
        r = self.ctl("test-connector")
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log.read_text()
        self.assertIn("go test", log); self.assertIn("-tags lab windowslab", log)
        self.assertIn("WIN_LAB_DC_ADDR=10.9.8.7", log); self.assertIn("WIN_LAB_TLS_NAME=dc1.win.activediq.test", log)
        self.assertIn(f"WIN_LAB_CA={self.ca}", log); self.assertIn(f"WIN_LAB_ENV={self.envf}", log)
        for tool in ("virsh", "virt-install", "qemu-img", "xorriso"):
            self.assertNotRegex(log, rf"(?m)^{tool} ")
        self.assertNotIn(SECRET, log + r.stdout + r.stderr)
        self.assertIn("verification ON", r.stdout)
        self.assertEqual(len(list((self.d / "logs").glob("connector-*.log"))), 1)

    def test_vm_lifecycle_commands_refused_in_external_mode(self):
        for cmd in ("up", "reset", "down", "destroy"):
            r = self.ctl(cmd)
            self.assertNotEqual(r.returncode, 0, cmd); self.assertIn("external mode", r.stderr)
        self.assertEqual(self.log.read_text(), "")  # nothing was executed

    def test_misconfiguration_fails_loudly(self):
        self.assertIn("WIN_LAB_DC_ADDR", self.ctl("test-connector", WIN_LAB_DC_ADDR="").stderr)
        self.assertIn("plain IP", self.ctl("test-connector", WIN_LAB_DC_ADDR="1.2.3.4;rm").stderr)
        self.assertIn("plain DNS", self.ctl("test-connector", WIN_LAB_TLS_NAME="a b").stderr)
        self.assertIn("CA file not found", self.ctl("test-connector", WIN_LAB_CA=str(self.d / "none")).stderr)
        self.assertIn("credentials file not found", self.ctl("test-connector", WIN_LAB_ENV=str(self.d / "none")).stderr)
        self.envf.chmod(0o644)
        self.assertIn("0600", self.ctl("test-connector").stderr)
        self.assertNotIn("go test", self.log.read_text())  # never reached the tests

    def test_unknown_mode_rejected(self):
        self.assertNotEqual(self.ctl("info", WIN_LAB_MODE="cloud").returncode, 0)

    def test_guest_init_is_secret_free_and_external_aware(self):
        init = (LAB / "guest/external-init.ps1").read_text()
        self.assertIsNone(re.search(r"Wl-[0-9a-f]{20}", init))
        self.assertIn("external = $true", init); self.assertIn("DC1", init)
        self.assertIn("$c.external", (LAB / "guest/boot.ps1").read_text())

    def test_rerunnable_guest_scripts_do_not_require_lab_json(self):
        """dc.ps1 deletes lab.json when provisioning ends (Remove-LabSecrets); the scripts the runbook tells a
        human to re-run afterwards must therefore fall back to AD instead of reading lab.json."""
        g = LAB / "guest"
        common = (g / "common.ps1").read_text()
        self.assertIn("Remove-Item \"$script:LabDir\\lab.json\"", common)  # the premise: it is deleted
        self.assertRegex(common, r"function Get-LabContext[\s\S]*Test-Path[\s\S]*Get-ADDomain")
        for n in ("audit-gpo.ps1", "entra-ready.ps1"):
            t = (g / n).read_text()
            self.assertIn("Get-LabContext", t, n)
            self.assertNotIn("Get-LabConfig", t, n)
        rb = (LAB.parent.parent / "knowledge/development/runbooks/windows-lab.md").read_text()
        self.assertNotIn("so do it before step 7", rb)


class GuestStageOrdering(unittest.TestCase):
    """T-0496: static proof (no PowerShell in CI) of the pending-restart path and of loud failures. Each assertion
    fails on the original dc.ps1/boot.ps1, which set 'promoted' before Install-ADDSForest and died silently."""

    def dc(self):
        return (LAB / "guest/dc.ps1").read_text()

    def start_block(self):
        d = self.dc()
        return d[d.index("'start' {"):d.index("'promoted' {")]

    def test_pending_restart_after_feature_install_reboots_and_resumes_at_start(self):
        b = self.start_block()
        self.assertRegex(b, r"\$feat = Install-WindowsFeature")
        self.assertIn("RestartNeeded", b)
        self.assertLess(b.index("RestartNeeded"), b.index("Restart-Computer"))
        self.assertLess(b.index("Restart-Computer"), b.index("Install-ADDSForest -DomainName"))
        self.assertRegex(b, r"Restart-Computer -Force\s+return")  # stops before promotion; stage stays 'start'
        self.assertIn("feature-reboot", b)  # one-shot marker: no reboot loop

    def test_stage_promoted_only_after_install_addsforest_succeeds(self):
        b = self.start_block()
        self.assertLess(b.index("Install-ADDSForest -DomainName"), b.index("Set-Stage 'promoted'"))
        self.assertIn("-NoRebootOnCompletion ", b); self.assertNotIn("-NoRebootOnCompletion:$false", b)
        self.assertLess(b.index("Set-Stage 'promoted'"), b.rindex("Restart-Computer"))

    def test_stage_failure_is_logged_without_dying_silently(self):
        for n in ("boot.ps1",):  # single file by design
            t = (LAB / "guest" / n).read_text()
            self.assertRegex(t, r"try \{[\s\S]*dc\.ps1[\s\S]*member\.ps1[\s\S]*\} catch \{[\s\S]*Write-LabLog[^\n]*Exception\.Message")
            self.assertIn("exit 1", t)
        catch = (LAB / "guest/boot.ps1").read_text().split("catch {")[1]
        self.assertNotIn("$c.", catch)  # never log config values (secrets)

    def test_adcs_installed_only_after_promotion(self):
        """Install-ADDSForest refuses with 'Certificate Server is installed' (VM 119), so ADCS comes after promotion."""
        d = self.dc()
        self.assertNotIn("ADCS-Cert-Authority", self.start_block())
        promoted = d[d.index("'promoted' {"):d.index("'configure' {")]
        self.assertLess(promoted.index("Install-WindowsFeature ADCS-Cert-Authority"), promoted.index("Install-AdcsCertificationAuthority"))

    def test_external_and_local_modes_share_the_same_dc_path(self):
        """external mode skips only NIC setup in boot.ps1; the DC promotion path is the one tested above."""
        boot = (LAB / "guest/boot.ps1").read_text()
        self.assertIn("if (-not $external)", boot)
        self.assertIn("& C:\\lab\\dc.ps1", boot)
        self.assertIn("catch", boot.split("& C:\\lab\\dc.ps1")[1])  # failure handler covers both modes


if __name__ == "__main__":
    unittest.main()
