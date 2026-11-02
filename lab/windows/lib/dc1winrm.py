"""Shared WinRM helper for lab workers talking to dc1 (Proxmox VM 119): HTTP 5985, NTLM, Administrator,
lab network only (A-0025). Credentials come from the gitignored lab env file and are never printed.
Callers must already hold the dc1 lock (lab/windows/bin/with-dc1-lock). Needs: pip install pywinrm requests-ntlm.
Introduced by T-0833; agent-verify and gssapi-lab carry older copies of the same code (follow-up chore).
"""
import base64, hashlib, os, sys, time

try:
    from winrm.protocol import Protocol
except ImportError:
    sys.exit("dc1winrm: pip install pywinrm requests-ntlm")


def load_env(repo):
    env = dict(os.environ)
    path = env.get("WIN_LAB_ENV") or os.path.join(repo, "lab", "windows", ".win-lab.env")
    if not os.path.exists(path):
        sys.exit(f"lab env file not found: {path} (set WIN_LAB_ENV; runbook section 10)")
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env.setdefault(k, v.strip().strip('"'))
    return env


class DC:
    def __init__(self, addr, password):
        self.p = Protocol(endpoint=f"http://{addr}:5985/wsman", transport="ntlm", username="Administrator",
                          password=password, read_timeout_sec=900, operation_timeout_sec=800)

    def _open_shell(self):
        """open_shell with a retry: right after another shell closes, WinRM can answer 500 ERROR_KEY_DELETED
        (0x800703FA, the Administrator profile hive is still unloading). Nothing has run yet, so retrying is safe."""
        for attempt in range(5):
            try:
                return self.p.open_shell()
            except Exception as e:  # noqa: BLE001 - winrm raises several types for the same transient fault
                if attempt == 4 or "marked for deletion" not in str(e):
                    raise
                time.sleep(3)

    def ps(self, script):
        """Run PowerShell on dc1; returns (exit code, stdout text)."""
        sh = self._open_shell()
        enc = base64.b64encode(script.encode("utf-16le")).decode()
        cid = self.p.run_command(sh, "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand", enc])
        out, _err, rc = self.p.get_command_output(sh, cid)
        self.p.cleanup_command(sh, cid)
        self.p.close_shell(sh)
        text = out.decode(errors="replace")
        text = "\n".join(l for l in text.splitlines() if not l.startswith("#< CLIXML") and not l.startswith("<Objs"))
        return rc, text

    def put_bytes(self, data, dst):
        sh = self._open_shell()
        ps = (f"$o=[IO.File]::Create('{dst}');$i=[Console]::OpenStandardInput();$b=New-Object byte[] 65536;"
              "while(($n=$i.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n)};$o.Close()")
        cid = self.p.run_command(sh, "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand",
                                                    base64.b64encode(ps.encode("utf-16le")).decode()])
        for i in range(0, len(data), 32000):
            self.p.send_command_input(sh, cid, data[i:i + 32000])
        self.p.send_command_input(sh, cid, b"", end=True)
        self.p.get_command_output(sh, cid)
        self.p.cleanup_command(sh, cid)
        self.p.close_shell(sh)
        _rc, out = self.ps(f"(Get-FileHash '{dst}').Hash")
        if hashlib.sha256(data).hexdigest().upper() not in out:
            sys.exit(f"upload to {dst} corrupted (sha256 mismatch)")

    def put(self, src, dst):
        self.put_bytes(open(src, "rb").read(), dst)
