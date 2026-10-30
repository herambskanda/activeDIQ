---
title: "Runbook: the Windows Server 2025 lab (local KVM, evaluation licence)"
date: 2026-10-23
updated: 2026-10-27
status: draft
owner: devops-engineer
ticket: T-0254
---

# Runbook: the Windows Server 2025 lab

The lab for everything Samba cannot prove (Windows event logs, GPO/audit policy, NTLM events, real
LDAPS/WS2025 hardening behaviour, ADWS, native components — see `ad-lab.md` §6). Chosen in D-0003
(option a): **local evaluation VMs on KVM, free**. One DC (`dc1`) and one member/file server (`fs1`) in
a throwaway forest. Code: `lab/windows/`. Samba stays the default lab (`ad-lab.md`); use this one only
for tests tagged `windowslab`.

## 1. Quick start

Host needs: Linux x86-64 with `/dev/kvm`, ~45 GB free (thin-provisioned qcow2, ≈15 GB real use per VM
plus the 5 GB ISO), 8 GB spare RAM, and
`sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients virtinst ovmf xorriso netcat-openbsd`
(your user in groups `libvirt` and `kvm`). Apple Silicon cannot run this lab.

```bash
make windows-lab-preflight        # tooling, KVM, disk space — no changes
make windows-lab-up               # the one command: ISO download, both VMs, domain, join, "clean" snapshot (~45 min first run)
make windows-lab-reset            # revert both VMs to the clean snapshot (minutes)
make lab-test-connector-windows   # internal/connector/ad against dc1 over LDAPS; log stored under windows-lab-runs/
make windows-lab-down | windows-lab-destroy | windows-lab-rebuild | windows-lab-status
make lab-test-windows-unit        # offline proof of the controller (stub hypervisor; part of make ci)
```

| Thing | Value |
| --- | --- |
| Domain / NetBIOS / base DN | `win.activediq.test` / `WINLAB` / `DC=win,DC=activediq,DC=test` (separate from the Samba lab's `lab.activediq.test`) |
| Network | libvirt NAT network `diq-win-lab`, `192.168.77.0/24`; host `.1`, `dc1` `.10`, `fs1` `.11` |
| LDAPS | `ldaps://192.168.77.10:636`; the certificate name is `dc1.win.activediq.test` (tests set the TLS name, no `/etc/hosts` needed) |
| Trust anchor | `lab/windows/.win-lab-ca.pem` — the lab's own enterprise root CA, exported by `up`. Never skip verification |
| Service account | `svc-activediq@win.activediq.test`, delegated on `OU=Managed` only (not Domain Admins) |
| fs1 | member server, share `\\fs1\Lab`, file-share and file-system auditing on, WinRM over HTTPS 5986 |

## 2. How it works

`lab/windows/bin/windows-lab` drives `virsh`/`virt-install`. Per VM it builds a small **config CD**
(`CIDATA`) holding `autounattend.xml`, the guest scripts and `lab.json` (generated secrets), attached
beside the evaluation ISO. Windows Setup installs unattended; first logon copies the CD to `C:\lab` and
runs `boot.ps1`, a reboot-safe staged script: `dc.ps1` (promote forest → enterprise root CA, which
issues dc1's LDAPS certificate by autoenrolment → OU/service account/delegation → Recycle Bin →
`audit-gpo.ps1` → `entra-ready.ps1`), then `member.ps1` on fs1 (join, share, auditing, WinRM-HTTPS).
At the end each guest **deletes `lab.json` and the answer file**. `up` then shuts both VMs down, takes
the internal snapshot `clean` on each, and restarts them. `reset` = `snapshot-revert … clean --running`.

## 3. Credentials (no secrets committed)

Passwords are random per lab (`Wl-<28 hex>-aA1!`), written to `lab/windows/.win-lab.env` (mode 0600,
gitignored) and never printed or put in argv or logs. They exist in three places only: that file, the
0600 config CD under `lab/windows/.state/` (also gitignored), and — until provisioning ends — `C:\lab`
in the guest. `windows-lab-destroy` deletes the file, the CD and the disks. The tracked answer-file
template contains only the `@@ADMINPW@@` placeholder (the offline test enforces both facts). The
evaluation ISO is never committed.

## 4. Evaluation licence, expiry, rearm

- Windows Server 2025 Evaluation runs **180 days** from first boot, then shuts down roughly hourly
  (licence terms `[UNVERIFIED]`: confirm on the [Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025)
  page; recorded in the licence register).
- Policy (director note on T-0254): **rebuild, don't rearm.** `make windows-lab-rebuild` takes ~45 min,
  is scripted and reproducible; `slmgr /rearm` is not used. Note the build date in the board when a lab
  is built; rebuild by day ~150. Check inside a guest with `slmgr /dlv`.
- Download URL: the default is the Evaluation Center fwlink `[UNVERIFIED]`. If Microsoft moves it, set
  `WIN_LAB_ISO_URL`, or place the ISO at `lab/windows/.state/ws2025-eval.iso`. Pin the checksum for
  rebuilds with `WIN_LAB_ISO_SHA256` (the first download records its sha256 next to the ISO).
- The setup answer file picks image index 2 (Standard Evaluation, Desktop Experience) `[UNVERIFIED]`;
  change `/IMAGE/INDEX` in `guest/autounattend.xml.tmpl` if the ISO orders editions differently.

## 5. Audit and NTLM hooks (dc1)

`guest/audit-gpo.ps1` (idempotent) creates the GPO `Lab - DC audit and NTLM`, linked to
`OU=Domain Controllers`:

| Need | How |
| --- | --- |
| Event **4776** (NTLM credential validation) and 4768/4769/4624/4625/4740/4720/4738/5136/4662 | Advanced audit subcategories enabled success+failure with `auditpol`; `SCENoApplyLegacyAuditPolicy=1` in the GPO; 512 MB Security log |
| Events **8001–8004** (`Microsoft-Windows-NTLM/Operational`: 8001 outgoing, 8002 incoming, 8003 in-domain, 8004 DC) | GPO values `AuditReceivingNTLMTraffic=2`, `RestrictSendingNTLMTraffic=1` (MSV1_0) and `AuditNTLMInDomain=7` (Netlogon); the log is enabled with `wevtutil` |
| **NTLM restriction** | Audit-only by default. A test sets `RestrictNTLMInDomain` in the same GPO (`Set-GPRegistryValue`), then `make windows-lab-reset` returns to audit-only |
| Read events | fs1/host: `Get-WinEvent -ComputerName dc1.win.activediq.test -FilterHashtable @{LogName='Security';Id=4776}` over WinRM/RPC, or an agent on dc1 |

Value choices come from Microsoft's NTLM-auditing documentation and are **`[UNVERIFIED]` until the first real
run** records each event ID appearing; the first operator pastes the observed IDs into
`windows-lab-runs/first-build.md`.

## 6. Entra Connect readiness (G9)

`guest/entra-ready.ps1` prepares the AD side only: `OU=Managed/EntraSync`, an extra UPN suffix
(`lab.activediq.example`, replace it with the Entra tenant's verified domain), two accounts
`g9-standard` and `g9-protected` (member of Account Operators → AdminSDHolder-protected, the G9 subject),
Recycle Bin on; report in `C:\lab\entra-ready.txt`. **Entra Connect itself is not installed**: it needs
a tenant Global Admin sign-in (CEO action, as in `ad-lab.md` §5) and the M365 sandbox. Follow-up once
the sandbox is bootstrapped: install Entra Connect on fs1 (not on the DC), sync `OU=EntraSync`, enable
password writeback, run G9.

## 7. Run logs

`make lab-test-connector-windows` tees `go test -v -tags 'lab windowslab' ./internal/connector/ad/` to
`knowledge/development/runbooks/windows-lab-runs/connector-<UTC>.log`. The tests (`windows_lab_test.go`)
bind as the service account over LDAPS with the lab CA, check `defaultNamingContext` and the paging/SD
controls, and prove a wrong password and an untrusted CA both fail. Logs contain no credentials.
Commit the log that backs a ticket's evidence.

## 8. Status of this runbook — read this

The tooling, the offline test (stub hypervisor, in `make ci`) and the Go tests are done. **The VMs have not
been built yet**: the build host lacked libvirt/QEMU and a ~5 GB download plus ~45 min were out of scope for
the implementing session. Everything under §5 and the ISO URL/edition index are untested against a real
guest. First operator: install the §1 packages, run `make windows-lab-up`, fix what the real Setup
reveals in `guest/`, run `make lab-test-connector-windows`, commit the log and `first-build.md`, then mark
this runbook `reviewed`.

## 9. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `missing: virsh …` / `/dev/kvm` | install §1 packages; enable virtualisation in firmware; `sudo usermod -aG libvirt,kvm $USER` and re-login |
| `up` times out on dc1:636 | `virsh -c qemu:///system console diq-win-dc1` is disabled (no serial); use `virt-viewer`; read `C:\lab\provision.log` in the guest. A failed stage logs `FAILED stage=…: <exception>` there (T-0496); a pending role-install restart reboots once and resumes at stage `start`; ADCS is installed only in stage `promoted` (it blocks Install-ADDSForest) |
| Setup stops at "select image" | wrong `/IMAGE/INDEX` (§4) |
| Net clash with `192.168.77.0/24` | change `SUBNET` in `windows-lab` and `winBind`/`WIN_LAB_DC_ADDR` |
| Disk pressure | `windows-lab-destroy` frees the disks; the ISO is kept, delete it by hand if needed |

## 9. TM-F-NTLM proof (T-0256, directory half)

Offline (runs in `go test ./internal/connector/ad`): `TestNTLMStaticGuard` fails if the connector
package references any NTLM/GSSAPI/digest/anonymous bind, imports `net/http`, an NTLM/SMB/Kerberos
library or `os/exec`, or opens/stats a path. Lab (`-tags lab`, Samba) and Windows lab
(`-tags 'lab windowslab'`): `TestLabNoSideDialOnPlantedUNC` / `TestWindowsLabNoSideDialOnPlantedUNC`
plant a user with a UNC `homeDirectory`/`profilePath`/`scriptPath` at a local attacker listener,
bind+search+read it through the connector with a recording dialer, and assert every dial is the DC
and the listener sees zero connections.

Still needed from a human run on the Windows lab (evidence for T-0256 AC1/AC2): set
`RestrictNTLMInDomain` in the lab GPO (§5), run `make lab-test-connector-windows`, then collect
events 4776 (dc1 Security) and 8001–8004 (`Microsoft-Windows-NTLM/Operational`) for the connector's
source address over the run window — expected none for the connector — plus a packet capture on the
attacker host (expected empty). Attach both to `windows-lab-runs/`.

## 10. External host: prepare Proxmox VM 112 (T-0428)

The CEO supplied an existing Windows Server 2025 Evaluation VM (Proxmox VM 112, 8 GiB, 4 cores, 60 GB)
as `dc1`, instead of local KVM. Factory tooling never touches the VM; a human does steps 1–6 once.
No `fs1` in this mode (member-server tests are out of scope until a second VM exists).

**Human steps (inside the VM unless stated)**

1. **Hostname.** Elevated PowerShell: `Rename-Computer -NewName DC1 -Restart`.
2. **Static IP** (use your Proxmox network values; the DC is its own DNS):
   `New-NetIPAddress -InterfaceAlias Ethernet -IPAddress <DC_IP> -PrefixLength 24 -DefaultGateway <GATEWAY>` then
   `Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses <DC_IP>` (check the alias with `Get-NetAdapter`).
3. **Copy the guest scripts** (`lab/windows/guest/*.ps1` from the repo) to the VM, e.g. `C:\guest\`.
4. **Initialise:** `powershell -ExecutionPolicy Bypass -File C:\guest\external-init.ps1 -DcIp <DC_IP>`.
   It creates `C:\lab`, generates random passwords into `C:\lab\lab.json` (ACL: SYSTEM + Administrators) and
   a host-format `C:\lab\win-lab.env`. Passwords are not printed.
5. **Provision:** `powershell -ExecutionPolicy Bypass -File C:\lab\boot.ps1`. It runs `dc.ps1` (forest
   `win.activediq.test`, enterprise root CA, LDAPS cert, `svc-activediq`, then `audit-gpo.ps1` and
   `entra-ready.ps1`), reboots by itself and resumes through the `LabResume` task. Done when
   `C:\lab\provision.log` ends with `dc1 provisioned` (~30 min). `audit-gpo.ps1` and `entra-ready.ps1` are
   idempotent and may be re-run by hand at any time, also after provisioning: `C:\lab\audit-gpo.ps1`,
   `C:\lab\entra-ready.ps1`. They do not need `lab.json` (deleted when provisioning finishes); they read the
   domain from AD. Only if a `g9-*` account is missing does `entra-ready.ps1` stop and ask for a re-provision.
6. **Export the CA and credentials:** `certutil -ca.cert C:\lab\ca.cer` then
   `certutil -encode C:\lab\ca.cer C:\lab\ca.pem`. Copy `ca.pem` and `win-lab.env` to the lab host
   (`scp`; never email or chat), then delete `C:\lab\win-lab.env` from the VM.
7. **Snapshot clean** (Proxmox host, VM shut down for a crash-consistent snapshot):
   `qm shutdown 112 && qm snapshot 112 clean --description "clean provisioned lab" && qm start 112`
   (or Datacenter → VM 112 → Snapshots → Take Snapshot, name `clean`). Revert later with `qm rollback 112 clean`.
   Note the build date: the evaluation licence is 180 days (§4); rebuild, don't rearm.

**On the lab host**

```bash
install -m 600 /path/from/scp/win-lab.env lab/windows/.win-lab.env     # gitignored
cp /path/from/scp/ca.pem lab/windows/.win-lab-ca.pem                   # gitignored
export WIN_LAB_MODE=external WIN_LAB_DC_ADDR=<DC_IP> WIN_LAB_TLS_NAME=dc1.win.activediq.test
# optional overrides: WIN_LAB_CA=<ca.pem path>  WIN_LAB_ENV=<env file path>
make windows-lab-preflight        # validates config, CA, env mode 0600 — no network
make lab-test-connector-windows   # go test -tags 'lab windowslab' against <DC_IP>:636, TLS name + CA verified
```

In external mode `up`, `reset`, `down` and `destroy` refuse (they manage libvirt VMs); nothing calls `virsh`.
Reset = `qm rollback 112 clean` by a human. Certificate verification is never disabled: the Go tests dial
`<DC_IP>:636` with `ServerName=$WIN_LAB_TLS_NAME` and the CA pool from `$WIN_LAB_CA`; a wrong CA fails
(`TestWindowsLab…` untrusted-CA test). `make lab-test-windows-unit` proves the mode offline (stub `go`/`virsh`,
checks refusals, misconfiguration errors and that the password never appears in argv, logs or stdout).
Status: **untested against VM 112 until a human completes the steps above** (the PowerShell is as untested as §8 says).

### TM-D26 on the Windows lab (T-0346)

`win_lab_tm26_test.go` (`TestWinLabTM26*`) plants state on the live domain head and restores it in `t.Cleanup`
(DACL and owner bytes read first). If a run is killed mid-test the head may be dirty: `qm rollback 112 clean`.
Run: `go test -tags 'lab windowslab' -run TestWinLabTM26 -v ./internal/connector/tier0`.
Results 2026-10-28 (dc1, WS2025): DACL (WRITE_DAC vs read-only twin), owner and callback ACEs 0x09/0x0B (allow) vs 0x0A
(deny) all classify as TM-D26 rules 2–4 expect. Windows refuses an LDAP write of `sIDHistory` (INSUFF_ACCESS_RIGHTS), so a
cross-domain Tier-0 `sIDHistory` cannot be planted in a one-domain lab: needs a second domain + trust (M2 follow-up).
`TestWinLabTM26GCOpens` is red on purpose until bug T-0619 (OpenGC fails on a real GC) is fixed.

## 11. Server MSI: build and the "refuses a domain controller" lab run (T-0702, T-0635)

**Toolchain.** WiX **5.0.2**, pinned in `tools/wix/Dockerfile` (MS-RL, no fee; WiX 6 and 7 carry the Open
Source Maintenance Fee, see the licence register; never bump past 5.x without a money decision). WiX needs
a real `msi.dll`, and the factory host is Linux, so the image runs it under Wine with the Windows .NET 8
runtime (archives pinned by SHA-256). The first `docker build` takes a few minutes. Native Linux `wix` does
not work: it fails with WIX0389 and a missing `msi.dll`. ICE validation needs Windows and does not run here;
run `wix msi validate <msi>` on a Windows host if you need it.

```bash
# from the repo root, with Server.wxs checked out (branch factory/T-0635, or main once it merged)
tools/wix/build-msi.sh packaging/windows/msi/Server.wxs lab/windows/.state/msi/ActiveDIQ-Server.msi   # prints the sha256
tools/wix/build-msi.sh tools/wix/testdata/broken.wxs /tmp/broken.msi    # must FAIL (WIX0094): proof the build catches defects
```

The build is not byte-reproducible yet (two builds of one source give different sha256), so record the
sha256 of the file you actually copy to the VMs. T-0702 build, from `factory/T-0635` at `ec3720e0`:
`ActiveDIQ-Server-0.1.0.0.msi`, sha256 `9863587114158c48f853a9ee631863ba7e22743d6f4c24e0843ed36ca77e17e3`,
in `lab/windows/.state/msi/` of the T-0702 worktree (gitignored; rebuild if it is gone).

**Run on dc1 (Proxmox VM 119, must refuse) and fs1 (control, must install).** Elevated PowerShell on each.
Copy the MSI plus `packaging/windows/Get-HostObservation.ps1` and `Test-MsiRefusesDc.ps1` to `C:\lab\`
(same folder; the driver calls the sibling script).

```powershell
Get-FileHash C:\lab\ActiveDIQ-Server.msi -Algorithm SHA256        # compare with the sha256 you recorded
cd C:\lab
.\Test-MsiRefusesDc.ps1 -MsiPath C:\lab\ActiveDIQ-Server.msi -LogPath C:\lab\msi.log > obs.json
```

- dc1: expect msiexec exit 1603, the log contains `cannot be installed on a domain controller`, no
  `C:\Program Files\activeDIQ`, no `activeDIQServer` service, no Uninstall entry, and `obs.json` says `refused`.
- fs1: expect exit 0, the install folder exists, `obs.json` says `installed`. Then clean up:
  `msiexec /x C:\lab\ActiveDIQ-Server.msi /qn`.
- Snapshot-revert dc1 if it shows leftovers (`qm rollback 119 clean`).

**Judge it on the repo host** (copy `obs.json` back, one per host: `obs-dc1.json`, `obs-fs1.json`):

```bash
go run ./tools/fitness/host evaluate obs-dc1.json
go run ./tools/fitness/host evaluate obs-fs1.json
```

Then add `windows-lab-runs/T-0635-msi-refuses-dc-<date>.md` with both sha256s, both `obs.json`, the
`msi.log` line holding the DC message, and the evaluate output. `tools/fitness/host` is on `factory/T-0635`
until that branch merges. Status: **the MSI has never been run on a Windows host.** This host has no route
to VM 119 (no SSH or WinRM), so a human runs the block above.
