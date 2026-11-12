"""fs1, the lab's domain-joined member server (T-1328, D-0022): pure PowerShell builders, parsers and judges.

Every value interpolated into PowerShell goes through ps_quote(), which only accepts a conservative character set and
returns a single-quoted literal. Secrets are passed in as arguments by the caller and never printed or stored here.
The WinRM transport is dc1winrm.py (parameterised by host and password key); lab only (A-0025, extended by D-0022).
"""
import base64, re

DOMAIN = "win.activediq.test"
NETBIOS = "WINLAB"
DC_ADDR_DEFAULT = "192.168.1.250"
COMPUTER = "FS1"
GMSA = "adiq-gmsa"            # sAMAccountName without the trailing $ (<= 15 chars)
LOCAL_USER = "adiq-std"       # local, non-admin; password = WIN_LAB_FS1_USER_PASSWORD in the lab env file
PREFIX = 24

_SAFE = re.compile(r"^[A-Za-z0-9._@:/\-]+$")


def ps_quote(v):
    """Single-quoted PowerShell literal for a value drawn from a restricted set. Anything else is refused."""
    v = str(v)
    if not _SAFE.match(v):
        raise ValueError("value not allowed in a PowerShell literal")
    return "'" + v + "'"


def ps_secret(v):
    """Single-quoted literal for a lab password: printable ASCII only (no control characters), embedded ' doubled.
    Inside a PowerShell single-quoted string nothing else is special, so this cannot be broken out of."""
    v = str(v)
    if not re.fullmatch(r"[\x20-\x7e]{12,128}", v):
        raise ValueError("password is not 12-128 printable ASCII characters")
    return "'" + v.replace("'", "''") + "'"


def net_ps(ip, gateway, dc):
    """Static IPv4 (the DHCP lease address, kept) with DNS = dc1. Idempotent."""
    return (
        "$a=Get-NetAdapter|?{$_.Status -eq 'Up'}|select -First 1;$i=$a.ifIndex;"
        "Set-NetIPInterface -InterfaceIndex $i -Dhcp Disabled;"
        f"if(-not (Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4|?{{$_.IPAddress -eq {ps_quote(ip)}}}))"
        f"{{Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4|Remove-NetIPAddress -Confirm:$false;"
        f"New-NetIPAddress -InterfaceIndex $i -IPAddress {ps_quote(ip)} -PrefixLength {PREFIX} -DefaultGateway {ps_quote(gateway)}|Out-Null}};"
        f"if(-not (Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue))"
        f"{{New-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -NextHop {ps_quote(gateway)}|Out-Null}};"
        f"Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses {ps_quote(dc)};"
        "Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4|%{'DNS='+($_.ServerAddresses -join ',')};"
        "'DHCP='+(Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4).Dhcp")


def join_ps(domain_admin_password):
    """Join the domain and restart. The caller expects the session to drop."""
    return (f"$p=ConvertTo-SecureString {ps_secret(domain_admin_password)} -AsPlainText -Force;"
            f"$c=New-Object pscredential('{NETBIOS}\\Administrator',$p);"
            f"Add-Computer -DomainName {ps_quote(DOMAIN)} -Credential $c -Force -Restart")


MEMBER_PS = "$s=Get-CimInstance Win32_ComputerSystem;'PartOfDomain='+$s.PartOfDomain;'Domain='+$s.Domain"

# On dc1: the KDS root key (a gMSA needs one; backdated so it is usable at once in a lab) and the gMSA, retrievable by FS1$ only.
GMSA_DC_PS = (
    "Import-Module ActiveDirectory;"
    "if(-not (Get-KdsRootKey)){Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))|Out-Null};"
    f"$m=Get-ADComputer {ps_quote(COMPUTER)};"
    f"if(-not (Get-ADServiceAccount -Filter \"Name -eq '{GMSA}'\")){{New-ADServiceAccount -Name {ps_quote(GMSA)} "
    f"-DNSHostName {ps_quote(GMSA + '.' + DOMAIN)} -PrincipalsAllowedToRetrieveManagedPassword $m "
    "-KerberosEncryptionType AES128,AES256 -Enabled $true}else{"
    f"Set-ADServiceAccount {ps_quote(GMSA)} -PrincipalsAllowedToRetrieveManagedPassword $m}};"
    f"$g=Get-ADServiceAccount {ps_quote(GMSA)} -Properties PrincipalsAllowedToRetrieveManagedPassword,Enabled;"
    "'gMSA='+$g.SamAccountName;'Enabled='+$g.Enabled;"
    "'Principals='+(($g.PrincipalsAllowedToRetrieveManagedPassword|%{(Get-ADObject $_).Name}) -join ',')")

def as_system(script):
    """Wrap a script so it runs as SYSTEM (the computer's domain identity) through a one-shot scheduled task, and its output
    comes back. The WinRM user is the local Administrator, which has no domain identity, so AD cmdlets there cannot reach dc1."""
    enc = base64.b64encode(script.encode("utf-16le")).decode()   # base64 alphabet only: safe inside the literal below
    return (
        "$d='C:\\ProgramData\\adiq-lab';New-Item -ItemType Directory -Force $d|Out-Null;$o=Join-Path $d 'sys.out';"
        "Remove-Item $o -ErrorAction SilentlyContinue;"
        f"$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{enc}'));"
        "$cmd='& {'+$s+'} *> '+\"'\"+$o+\"'\";"
        "$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)));"
        "Register-ScheduledTask -TaskName AdiqLabSys -Action $a -User 'SYSTEM' -RunLevel Highest -Force|Out-Null;Start-ScheduledTask AdiqLabSys;"
        "for($i=0;$i -lt 120;$i++){Start-Sleep 2;if((Get-ScheduledTask AdiqLabSys).State -ne 'Running'){break}};"
        "Unregister-ScheduledTask AdiqLabSys -Confirm:$false;Get-Content $o -ErrorAction SilentlyContinue")


# On fs1: the AD module, the gMSA installed. Test-ADServiceAccount is the proof.
GMSA_FS1_INNER = (
    "$ErrorActionPreference='Stop';try{Import-Module ActiveDirectory;"
    f"Install-ADServiceAccount {ps_quote(GMSA)};"
    f"'Test-ADServiceAccount='+(Test-ADServiceAccount {ps_quote(GMSA)})}}catch{{'ERR: '+$_.Exception.Message}}")
GMSA_FS1_PS = "Install-WindowsFeature RSAT-AD-PowerShell|Out-Null;" + as_system(GMSA_FS1_INNER)


def user_ps(password):
    """Local standard user: member of Users, never Administrators. Idempotent (resets the password)."""
    return (f"$p=ConvertTo-SecureString {ps_secret(password)} -AsPlainText -Force;"
            f"if(Get-LocalUser {ps_quote(LOCAL_USER)} -ErrorAction SilentlyContinue){{Set-LocalUser {ps_quote(LOCAL_USER)} -Password $p}}"
            f"else{{New-LocalUser {ps_quote(LOCAL_USER)} -Password $p -PasswordNeverExpires -Description 'activeDIQ lab standard user'|Out-Null}};"
            f"Add-LocalGroupMember -Group 'Users' -Member {ps_quote(LOCAL_USER)} -ErrorAction SilentlyContinue;"
            f"Remove-LocalGroupMember -Group 'Administrators' -Member {ps_quote(LOCAL_USER)} -ErrorAction SilentlyContinue;"
            f"'LocalUser='+(Get-LocalUser {ps_quote(LOCAL_USER)}).Name")


EVIDENCE_PS = (
    "'COMPUTERNAME='+$env:COMPUTERNAME;"
    "'OS='+(Get-CimInstance Win32_OperatingSystem).Caption;"
    "$s=Get-CimInstance Win32_ComputerSystem;'PartOfDomain='+$s.PartOfDomain;'Domain='+$s.Domain;"
    "'NLTEST='+((nltest /sc_verify:" + DOMAIN + ") -join ' | ');"
    + as_system("try{Import-Module ActiveDirectory -ErrorAction Stop;'Test-ADServiceAccount='+(Test-ADServiceAccount " + ps_quote(GMSA) + ")}catch{'Test-ADServiceAccount=ERR '+$_.Exception.Message}") + ";"
    "'ADMINS='+((Get-LocalGroupMember Administrators|%{$_.Name}) -join ',');"
    f"'USERS='+((Get-LocalGroupMember Users|%{{$_.Name}}) -join ',');"
    f"'LOCALUSER_ENABLED='+(Get-LocalUser {ps_quote(LOCAL_USER)}).Enabled;"
    "$n=Get-NetIPConfiguration|select -First 1;'IPV4='+$n.IPv4Address.IPAddress;'DNS='+($n.DNSServer.ServerAddresses -join ',');"
    "'DHCP='+(Get-NetIPInterface -InterfaceIndex $n.InterfaceIndex -AddressFamily IPv4).Dhcp;"
    "'NIC='+((Get-NetAdapter|%{$_.InterfaceDescription}) -join ',')")


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def problems(ev, dc_addr=DC_ADDR_DEFAULT):
    """Judge parsed EVIDENCE_PS output against the three acceptance criteria. -> list of strings (empty = pass)."""
    bad = []
    if ev.get("PartOfDomain") != "True" or ev.get("Domain", "").lower() != DOMAIN:
        bad.append(f"not joined to {DOMAIN} (PartOfDomain={ev.get('PartOfDomain')}, Domain={ev.get('Domain')})")
    nl = ev.get("NLTEST", "")
    if "NERR_Success" not in nl:
        bad.append("nltest /sc_verify did not report NERR_Success")
    if ev.get("Test-ADServiceAccount") != "True":
        bad.append(f"Test-ADServiceAccount is {ev.get('Test-ADServiceAccount')}, need True")
    admins = [a.lower() for a in ev.get("ADMINS", "").split(",") if a]
    if any(a.split("\\")[-1] == LOCAL_USER for a in admins):
        bad.append(f"{LOCAL_USER} is in the local Administrators group")
    users = [a.lower() for a in ev.get("USERS", "").split(",") if a]
    if not any(a.split("\\")[-1] == LOCAL_USER for a in users):
        bad.append(f"{LOCAL_USER} is not a member of local Users")
    if ev.get("LOCALUSER_ENABLED") != "True":
        bad.append(f"{LOCAL_USER} is not enabled")
    if dc_addr not in ev.get("DNS", "").split(","):
        bad.append(f"DNS is {ev.get('DNS')!r}, need dc1 ({dc_addr})")
    if ev.get("DHCP") != "Disabled":
        bad.append(f"IPv4 DHCP is {ev.get('DHCP')}, need Disabled (static)")
    if "VirtIO" not in ev.get("NIC", ""):
        bad.append("no VirtIO NIC")
    return bad
