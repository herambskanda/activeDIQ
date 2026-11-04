"""The dc1 LDAP policy the Windows lab proofs depend on (T-1265): signing required, channel binding always.

Pure functions (parse, judge, probe) so every caller and the offline tests share one definition. The WinRM transport
lives in dc1winrm.py. Nothing here prints or stores a credential; the probe sends a fixed dummy password.
"""
import socket

NTDS = r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
# The only values the lab may leave on dc1. 2 = "Require signing" / "Always" (Microsoft, 2020 LDAP channel binding and
# signing requirements: https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a).
REQUIRED = {"LDAPServerIntegrity": 2, "LdapEnforceChannelBindingTokens": 2}

# PowerShell that prints "<name> = <value>" per key, empty value when absent.
READ_PS = ("foreach($k in '%s'){ $k+' = '+((Get-Item '%s').GetValue($k)) }" % ("','".join(REQUIRED), NTDS))
# PowerShell that writes the REQUIRED table (names and values come from this module, not from a caller).
WRITE_PS = "; ".join("Set-ItemProperty '%s' -Name '%s' -Type DWord -Value %d" % (NTDS, k, v) for k, v in REQUIRED.items())

# The reset source (T-1265): the Default Domain Controllers Policy carries the Windows default
# `MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,1` in its GptTmpl.inf, and the Security
# Settings engine rewrites the registry value from it at boot and on refresh. A registry-only restore is undone by the next
# reset of that engine. The template line must read 4,2 ("4" = REG_DWORD) so the GPO and the registry agree.
GPO_GUID = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"  # fixed well-known id of the Default Domain Controllers Policy
GPO_PS_PRELUDE = (
    "$g='%s';$inf=Join-Path $env:SystemRoot ('SYSVOL\\domain\\Policies\\'+$g+'\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf');"
    "$ini=Join-Path $env:SystemRoot ('SYSVOL\\domain\\Policies\\'+$g+'\\GPT.INI');"
    "$pat='(?m)^MACHINE\\\\System\\\\CurrentControlSet\\\\Services\\\\NTDS\\\\Parameters\\\\LDAPServerIntegrity=(.*?)[ \\t\\r]*$';" % GPO_GUID)
# prints "GPO_LDAPServerIntegrity = <4,N>" (empty when the template does not define it)
GPO_READ_PS = GPO_PS_PRELUDE + "$m=[regex]::Match((Get-Content -Raw $inf),$pat);'GPO_LDAPServerIntegrity = '+$m.Groups[1].Value"
# Rewrites the template line to 4,2, bumps the computer half of the GPO version in GPT.INI and in AD so DCs reprocess it.
GPO_FIX_PS = (GPO_PS_PRELUDE +
    "$t=Get-Content -Raw $inf;if($t -match $pat){$t=[regex]::Replace($t,$pat,'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2')}"
    "else{$t=$t -replace '(?m)^\\[Registry Values\\]\\s*$',\"[Registry Values]`r`nMACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2\"};"
    "Set-Content -Path $inf -Value $t -Encoding Unicode;"
    "$i=Get-Content -Raw $ini;$v=[int]([regex]::Match($i,'(?m)^Version=(\\d+)').Groups[1].Value)+1;"
    "Set-Content -Path $ini -Value ([regex]::Replace($i,'(?m)^Version=\\d+','Version='+$v)) -Encoding ASCII;"
    "Import-Module ActiveDirectory;$d=(Get-ADDomain).DistinguishedName;"
    "Set-ADObject -Identity ('CN='+$g+',CN=Policies,CN=System,'+$d) -Replace @{versionNumber=$v};"
    "gpupdate /target:computer /force | Out-Null")

RESULT_NAMES = {0: "success", 8: "strongerAuthRequired", 49: "invalidCredentials", 53: "unwillingToPerform"}


def parse_policy(text):
    """'LDAPServerIntegrity = 1' lines -> {name: int | None}. Unknown lines are ignored; an empty value is None (absent)."""
    out = {}
    for line in text.splitlines():
        name, sep, val = line.partition("=")
        name, val = name.strip(), val.strip()
        if sep and name in REQUIRED:
            out[name] = int(val) if val.lstrip("-").isdigit() else None
    return out


def parse_gpo(text):
    """'GPO_LDAPServerIntegrity = 4,1' -> 1 (int), None when the line is empty/absent or not a REG_DWORD (type 4) value."""
    for line in text.splitlines():
        name, sep, val = line.partition("=")
        if sep and name.strip() == "GPO_LDAPServerIntegrity":
            t, _, n = val.strip().partition(",")
            return int(n) if t == "4" and n.isdigit() else None
    return None


def gpo_problems(gpo_value):
    """The GPO would reset the registry value at the next Security Settings run unless it also says 2."""
    if gpo_value == REQUIRED["LDAPServerIntegrity"]:
        return []
    return [f"Default Domain Controllers Policy sets LDAPServerIntegrity to {'nothing' if gpo_value is None else gpo_value} "
            f"(GptTmpl.inf), which resets the registry value at boot/refresh; need 2"]


def problems(values):
    """One sentence per required value that is not at its required setting, naming the value that was read."""
    out = []
    for name, want in REQUIRED.items():
        got = values.get(name)
        if got != want:
            out.append(f"{name} is {'absent' if got is None else got}, need {want}")
    return out


def _tlv(tag, body):
    if len(body) > 127:
        raise ValueError("probe message too long")
    return bytes([tag, len(body)]) + body


def bind_probe(host, port=389, timeout=10, dn="cn=signing-probe", password="not-a-password"):
    """Cleartext simple bind to 389. A DC that requires signing answers strongerAuthRequired (8) to a bind whose credentials are
    VALID (DSID-0C090343, "server requires binds to turn on integrity checking"); with a wrong DN or password it answers
    invalidCredentials (49) at either setting, so a dummy-credential probe cannot tell the two apart (measured on dc1 at 2/2,
    T-1265). Callers that judge enforcement must pass the lab service account (never printed). Returns (resultCode, name)."""
    bind = _tlv(0x60, b"\x02\x01\x03" + _tlv(0x04, dn.encode()) + _tlv(0x80, password.encode()))
    msg = _tlv(0x30, b"\x02\x01\x01" + bind)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(msg)
        data = s.recv(4096)
    # LDAPMessage SEQ { messageID INTEGER, bindResponse [APPLICATION 1] { resultCode ENUMERATED ... } }
    if not data or data[0] != 0x30:
        raise ValueError(f"not an LDAP response: {data[:8].hex()}")
    i = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
    i += 2 + data[i + 1]  # skip messageID
    if data[i] != 0x61:
        raise ValueError(f"not a bindResponse: tag {data[i]:#x}")
    i += 2 if data[i + 1] < 0x80 else 2 + (data[i + 1] & 0x7F)
    if data[i] != 0x0A:
        raise ValueError("bindResponse has no resultCode")
    code = data[i + 2]
    return code, RESULT_NAMES.get(code, f"resultCode{code}")
