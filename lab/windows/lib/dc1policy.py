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


def bind_probe(host, port=389, timeout=10):
    """Cleartext simple bind with a dummy password to 389. A DC that requires signing answers strongerAuthRequired (8) before
    it looks at the credentials; one that does not answers invalidCredentials (49). Returns (resultCode, name)."""
    bind = _tlv(0x60, b"\x02\x01\x03" + _tlv(0x04, b"cn=signing-probe") + _tlv(0x80, b"not-a-password"))
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
