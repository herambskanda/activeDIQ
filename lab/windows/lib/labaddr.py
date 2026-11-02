"""The Windows lab DC address has no default (T-1279).

dc1 has moved before (A-0032: an IP clash on its old address), and a hardcoded fallback silently aims a driver that
reboots, installs and clears logs at whatever device holds the old address. Every driver calls require_dc_addr()
before it opens any connection (and before it takes the dc1 lock); a missing or malformed key is a hard error
that names WIN_LAB_DC_ADDR. Process environment wins over the lab env file, as in the drivers' own loaders.
"""
import os, re, sys

_PLAIN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.:-]*[A-Za-z0-9])?$")  # same rule as bin/windows-lab external mode


def read_env_file(path):
    env = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v.strip().strip('"')
    return env


def require_dc_addr(prog, repo, environ=None):
    environ = os.environ if environ is None else environ
    path = environ.get("WIN_LAB_ENV") or os.path.join(repo, "lab", "windows", ".win-lab.env")
    if not os.path.exists(path):
        sys.exit(f"{prog}: lab env file not found: {path} (set WIN_LAB_ENV; runbook section 10)")
    addr = environ.get("WIN_LAB_DC_ADDR") or read_env_file(path).get("WIN_LAB_DC_ADDR", "")
    if not addr:
        sys.exit(f"{prog}: WIN_LAB_DC_ADDR is not set (in {path} or the environment); there is no default DC "
                 f"address. Set it to dc1's current IP or host name (runbook section 10).")
    if not _PLAIN.match(addr):
        sys.exit(f"{prog}: WIN_LAB_DC_ADDR is not a plain IP/host name")
    return addr
