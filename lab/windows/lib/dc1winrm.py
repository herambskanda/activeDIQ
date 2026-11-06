"""WinRM transport to the lab DC (HTTP 5985, NTLM, lab only; CEO authorisation A-0025). Shared by gssapi-lab and dc1-policy.
Credentials come from the lab env file (WIN_LAB_ENV) and are never printed. Wrap every caller in with-dc1-lock."""
import base64, hashlib, os, sys, time

try:
    from winrm.protocol import Protocol
except ImportError:
    Protocol = None

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def load_env(tool):
    """-> (env dict, env file path, dc address). Exits with a one-line message when the env file is missing."""
    if Protocol is None:
        sys.exit(f"{tool}: pip install pywinrm requests-ntlm")
    path = os.environ.get("WIN_LAB_ENV") or os.path.join(REPO, "lab", "windows", ".win-lab.env")
    if not os.path.exists(path):
        sys.exit(f"{tool}: lab env file not found: {path} (set WIN_LAB_ENV)")
    env = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v.strip().strip('"')
    return env, path, os.environ.get("WIN_LAB_DC_ADDR") or env.get("WIN_LAB_DC_ADDR", "192.168.1.250")


def strip(o):  # drop the CLIXML progress noise PowerShell writes on stderr/stdout
    return "\n".join(l for l in o.splitlines() if not l.startswith(("#< CLIXML", "<Objs")))


def _protocol(env, addr):
    return Protocol(endpoint=f"http://{addr}:5985/wsman", transport="ntlm", username="Administrator",
                    password=env["WIN_LAB_ADMIN_PASSWORD"], read_timeout_sec=900, operation_timeout_sec=800)


def make_ps(env, addr):
    def ps(script):
        p = _protocol(env, addr)
        sh = p.open_shell()
        enc = base64.b64encode(script.encode("utf-16le")).decode()
        cid = p.run_command(sh, "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand", enc])
        out, err, rc = p.get_command_output(sh, cid)
        try:  # a clock change can break the session teardown; the command already ran
            p.cleanup_command(sh, cid)
            p.close_shell(sh)
        except Exception:
            pass
        return rc, strip(out.decode(errors="replace"))
    return ps


def make_put(env, addr):
    def put(src, dst):
        data = open(src, "rb").read()
        p = _protocol(env, addr)
        sh = p.open_shell()
        s = (f"$o=[IO.File]::Create('{dst}');$i=[Console]::OpenStandardInput();$b=New-Object byte[] 65536;"
             "while(($n=$i.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n)};$o.Close()")
        cid = p.run_command(sh, "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand",
                                               base64.b64encode(s.encode("utf-16le")).decode()])
        for i in range(0, len(data), 32000):
            p.send_command_input(sh, cid, data[i:i + 32000])
        p.send_command_input(sh, cid, b"", end=True)
        p.get_command_output(sh, cid)
        p.cleanup_command(sh, cid)
        p.close_shell(sh)
    return put


class DC:
    """Stateful wrapper for drivers that run many commands (agent-unenrolled-verify, T-0833). The make_ps/make_put
    closures above stay for the one-shot callers."""

    def __init__(self, env, addr):
        self.p = _protocol(env, addr)

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
        return rc, strip(out.decode(errors="replace"))

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
