---
title: T-0635 lab run — the server MSI refuses a domain controller
status: draft
owner: windows-engineer
---

# T-0635: server MSI on dc1 (2026-10-30)

Acceptance 1: given the MSI on the lab dc1, it exits non-zero with the DC message, installs nothing, and the
Windows host proof reports HOST-DC-REFUSED ok. **Result: passed.** fs1 (the install control) is not part of
this acceptance and was not run; the MSI has still never installed successfully on any host.

- Host: dc1 = Proxmox VM 119, Windows Server 2025 Standard Evaluation, build 26100, ProductType 2, DomainRole 5.
- Transport: WinRM 5985/NTLM (A-0025, lab only), under the dc1 flock. Work dir `C:\lab\T-0635` (removed afterwards).
- MSI: built by `tools/wix/build-msi.sh packaging/windows/msi/Server.wxs` (WiX 5.0.2 under Wine),
  `ActiveDIQ-Server-0.1.0.0.msi`, sha256 `dd8e24cc0664e70328f4a95fcedb532ce3ca9ca9122ec3cfb077bcbb8702bbb8`
  (compared on dc1 with Get-FileHash: equal). Source: factory/T-0635 after merging main.

## Evidence

`msiexec /i ... /qn /norestart /l*v` exit code **1603**. Key lines of the verbose log:

```
Property(S): MsiNTProductType = 2
MSI (s) (C8:90) [12:43:29:193]: Product: activeDIQ Server -- activeDIQ Server cannot be installed on a domain controller. Install it on a member server (Windows Server 2019 or later); domain controllers host only the activeDIQ agent.
Action ended 12:43:29: LaunchConditions. Return value 3.
Action ended 12:43:29: INSTALL. Return value 3.
MSI (s) (C8:90) [12:43:29:232]: Product: activeDIQ Server -- Installation failed.
... Product Name: activeDIQ Server. Product Version: 0.1.0.0. ... Installation success or error status: 1603.
```

Nothing installed: no `C:\Program Files\activeDIQ`, no `activeDIQServer` service, no Uninstall entry.

`obs-dc1.json` (output of `Test-MsiRefusesDc.ps1`, which calls `Get-HostObservation.ps1`):

```json
{
    "profile":  "windows",
    "installer":  {
                      "on_domain_controller":  true,
                      "refused":  true,
                      "installed":  false
                  }
}
```

`go run ./tools/fitness/host evaluate obs-dc1.json`:

```
ok     HOST-DC-REFUSED               
INACTIVE HOST-SERVICE-NOT-PRIVILEGED  no service identity observed
INACTIVE HOST-FILE-PERMISSIONS        no config, keytab, keystore or TLS files observed
INACTIVE HOST-NO-DEFAULT-CREDENTIAL   no booted first-run state observed
INACTIVE HOST-NO-PLAINTEXT-LISTENER   no booted first-run state observed
INACTIVE HOST-SETUP-SECRET-SINGLE-USE the product has no one-time setup secret yet
INACTIVE HOST-NO-DUMPS                no dump posture observed
INACTIVE HOST-REMOTE-DSN-FULL-TLS     no DSN probes
fitness-host: ok
```

The other cases stay INACTIVE: they need a booted product, which a refused MSI does not produce.

## Defects the run found (fixed in this change)

1. `Test-MsiRefusesDc.ps1`: under StrictMode, reading `.DisplayName` of an Uninstall subkey that has none threw,
   so the driver died after msiexec and printed no observation. It now reads the value with `GetValue`.
2. `Get-HostObservation.ps1`: `Get-Acl` on the install directory threw when the install was refused (no
   directory). A missing directory is now an unobserved ACL section, not an error.

## dc1 before and after

Identical for everything this run touched: ProductType 2, DomainRole 5, `C:\lab` contents unchanged
(build, gssapi, junction-target, out, tools, 9 files, stage), no install directory, no service, no Uninstall
entry. The only difference is the Windows Installer service (Stopped before, Running after: it starts on
demand and idles out) and the running-service count (82 vs 91: demand-start services, unrelated). No policy,
registry or service configuration was changed.
