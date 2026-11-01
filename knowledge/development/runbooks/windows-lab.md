---
title: "Runbook: the Windows Server 2025 lab (local KVM, evaluation licence)"
date: 2026-10-23
updated: 2026-11-01
status: draft
owner: devops-engineer
ticket: T-0254
---

# Runbook: the Windows Server 2025 lab

The lab for everything Samba cannot prove (Windows event logs, GPO/audit policy, NTLM events, real
LDAPS/WS2025 hardening behaviour, ADWS, native components — see `ad-lab.md` §6). Chosen in D-0003
(option a): **local evaluation VMs on KVM, free**. In the local-KVM mode, a DC (`dc1`) and a member/file server
(`fs1`) in a throwaway forest; the live lab (§10) is `dc1` on Proxmox VM 119 plus, once a human has built it,
a child-domain DC `dc2` (§16). Code: `lab/windows/`. Samba stays the default lab (`ad-lab.md`); use this one only
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

Still needed from a worker run on dc1 over WinRM, under `with-dc1-lock` (§10; evidence for T-0256 AC1/AC2): set
`RestrictNTLMInDomain` in the lab GPO (§5), run `make lab-test-connector-windows`, then collect
events 4776 (dc1 Security) and 8001–8004 (`Microsoft-Windows-NTLM/Operational`) for the connector's
source address over the run window — expected none for the connector — plus a packet capture on the
attacker host (expected empty; the capture runs on the Linux lab host). Attach both to `windows-lab-runs/`.

## 10. External host: Proxmox VM 119 as dc1 (T-0428)

### Worker access to dc1: WinRM, lab only, one session at a time (A-0025, T-0839)

**Authorisation.** The CEO authorised workers to use WinRM against `dc1` (Proxmox VM 119, forest
`win.activediq.test`) on 2026-10-29 (A-0025). The limit is **lab only**: never a customer host, never any
host that is not this lab's `dc1`. If a ticket asks for WinRM or any remote session to anything else, block
it and raise a decision; this authorisation does not stretch.

**Transport.** WinRM over HTTP 5985 with NTLM as `Administrator`, on the lab network, as in `agent-verify`
(§13). The password comes from the gitignored lab env file (`WIN_LAB_ENV`; from a worktree it lives in the
main checkout's `lab/windows/`). Read it from the file in code; never print it, put it in argv, a log or a note.

**The lock rule: wrap every dc1 session in `with-dc1-lock`.** About seven tickets share dc1, and some
of them reboot it, change LDAP signing or channel-binding policy, install and remove the agent or clear the
Security log. Two sessions at once corrupt each other's result. So every worker session that talks to dc1
(WinRM, PowerShell remoting, or a test against its LDAP/LDAPS port) runs as:

```bash
lab/windows/bin/with-dc1-lock -- <your command>          # e.g. python3 my-winrm-session.py
```

It takes an exclusive `flock` on `/tmp/claude-1000/activediq-dc1.lock`, waits up to 3600 s if another
session holds it (printing who holds it: user, pid, branch, directory, start time, command), runs your
command, and passes its exit status through (75 = gave up waiting). Hold it for the *whole* session,
including the restore at the end; release by exiting. It is re-entrant, so `agent-verify` and
`windows-lab test-connector`, which take it themselves, can sit inside a wrapped command. Settings:
`DIQ_DC1_LOCK` (lock file), `DIQ_DC1_LOCK_WAIT` (seconds). A dc1 session that does not hold the lock is a
review blocker. Proof: `make lab-test-windows-unit` (`lab/windows/tests/test_with_dc1_lock.sh`). Leave dc1
as you found it (agent uninstalled, policy restored, test OUs removed): the next session starts from it.

**What WinRM cannot do.** A Proxmox snapshot, rollback or console (`qm …`) is a hypervisor operation, not a
dc1 session, and workers have no Proxmox access: if a run leaves dc1 beyond repair by script, raise an
`action new` for a rollback. Everything that runs *inside* dc1 is done by workers over WinRM.

**dc2 (child domain) is human-only.** A-0025 covers `dc1` only: no worker may open WinRM, PowerShell remoting or
any other session to `dc2` (VM, address or name), and the `with-dc1-lock` wrapper is not a licence to. In short,
every step inside dc2 is done by a human (§16); workers verify the child domain only through dc1 (T-1234). Extending the
authorisation to dc2 is a CEO decision, not a ticket step.

**fs1 does not exist.** There is no member server in this lab: only dc1 (VM 119). The `fs1` rows in §1–§2
describe the local-KVM mode, which was dropped. A human creates fs1 (A-0028; tickets T-0409, T-0413).
Until then no worker step may assume `fs1`, and proofs that need a member server stay blocked on A-0028.

### History: preparing the VM (T-0428)

The CEO supplied an existing Windows Server 2025 Evaluation VM (first Proxmox VM 112, then VM 119; 8 GiB,
4 cores, 60 GB) as `dc1`, instead of local KVM. The steps below were done once by a human, before WinRM
existed on it; VM 119 is provisioned (§10 status line), so they matter only for a rebuild. After that
rebuild, WinRM must be enabled again (`Enable-PSRemoting`, firewall, `AllowUnencrypted` on the lab network
only, as agent-verify expects) before workers can use it. No `fs1` in this mode.

**Rebuild steps (inside the VM unless stated)**

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
   `C:\lab\entra-ready.ps1` (workers: over WinRM, under `with-dc1-lock`). They do not need `lab.json` (deleted when provisioning finishes); they read the
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
Reset = `qm rollback <vmid> clean` on the Proxmox host (VM 119 for the first build; no worker has access, see the rule above). Certificate verification is never disabled: the Go tests dial
`<DC_IP>:636` with `ServerName=$WIN_LAB_TLS_NAME` and the CA pool from `$WIN_LAB_CA`; a wrong CA fails
(`TestWindowsLab…` untrusted-CA test). `make lab-test-windows-unit` proves the mode offline (stub `go`/`virsh`,
checks refusals, misconfiguration errors and that the password never appears in argv, logs or stdout).
Status: first build done 2026-10-28 on Proxmox VM 119 (log and notes in `windows-lab-runs/first-build.md`); `TestWindowsLab*` pass over verified LDAPS.

## Tier0 classifier on the Windows lab (T-0226)

`internal/connector/tier0/windows_lab_c5c15_test.go` (tags `lab windowslab`; not run by `make lab-test-connector-windows`, which
targets `./internal/connector/ad/` only). Run it with the same env as above:

```bash
go test -count=1 -v -tags 'lab windowslab' ./internal/connector/tier0 -run TestWindowsLab
```

Fixtures are created as Administrator (`WIN_LAB_ADMIN_PASSWORD`) under a throwaway `OU=t0226-*`; the DC-root DACL, the RBCD
attribute on a DC and `gPLink` of the Domain Controllers OU are changed and restored by cleanups (a failed restore says
`RESTORE … FAILED`: `qm rollback`). Classification runs as `svc-activediq`. Pinned: C5 (all DC computers), C15 (DC site),
C8 (KDS container + a child, CN=System, RID Manager$, Directory Service; the Password Settings Container is unreadable to the
service account and fails closed), C9 (GPO linked at the DC OU is tier0, an unlinked one is not), C11 (Get-Changes +
Get-Changes-All ⇒ tier0; Get-Changes alone ⇒ not), C12 (RBCD trustee on a DC). Not coverable on this lab (a single DC in the parent domain,
no RODC; the child domain exists only after §16 is done): RODC corroboration, cross-domain GPO links, gPLink option/order edge cases, >1500-member ranged groups
(Samba covers ranged retrieval); the ad-expert review of `c8Domain`/`c8SystemClasses` is separate (T-0620).
From a git worktree the credentials live in the main checkout: set `WIN_LAB_ENV` and `WIN_LAB_CA` to its `lab/windows/` files.

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

**Run on dc1 (Proxmox VM 119, must refuse) and fs1 (control, must install).** The dc1 run is a worker
step: over WinRM as `Administrator` (§10, A-0025), wrapped in `lab/windows/bin/with-dc1-lock`, using the
`DC` helper of `lab/windows/bin/agent-verify` for the upload (sha256-checked) and for running the
PowerShell below elevated. The fs1 control run needs a member server that **does not exist** (A-0028),
so it stays blocked until a human builds fs1; a dc1-only run still proves the refusal. Copy the MSI plus
`packaging/windows/Get-HostObservation.ps1` and `Test-MsiRefusesDc.ps1` to `C:\lab\`
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
- If dc1 shows leftovers, remove them over WinRM (`msiexec /x`, delete `C:\Program Files\activeDIQ`);
  a rollback (`qm rollback 119 clean`) needs the Proxmox host, so raise an `action new` only if scripts cannot fix it.

**Judge it on the repo host** (copy `obs.json` back, one per host: `obs-dc1.json`, `obs-fs1.json`):

```bash
go run ./tools/fitness/host evaluate obs-dc1.json
go run ./tools/fitness/host evaluate obs-fs1.json
```

Then add `windows-lab-runs/T-0635-msi-refuses-dc-<date>.md` with both sha256s, both `obs.json`, the
`msi.log` line holding the DC message, and the evaluate output. `tools/fitness/host` is on `factory/T-0635`
until that branch merges. Status: **the MSI has never been run on a Windows host.** Workers can now run the dc1 half over WinRM
(A-0025, under the dc1 lock); the fs1 half waits for fs1 (A-0028).

## 12. Agent identity harness (T-0613, for T-0557)

Creates `NT SERVICE\activeDIQAgent` with the ADR-0006 token (service SID `restricted`, `RequiredPrivileges` =
`SeChangeNotifyPrivilege`, data dir DACL service SID + SYSTEM + Administrators) on dc1 (T-0557), the only
Windows host in the lab. No agent MSI or service host exists, so the service binary is a lab-only stub that records `whoami`
output from inside the service token. This is not the installer.

```bash
make windows-agent-harness-build          # -> lab/windows/.state/agent-harness/svcstub.exe
# copy svcstub.exe and lab/windows/agent-harness/Install-AgentLabHarness.ps1 to dc1 (C:\lab\agent-harness\)
```
A worker does the copy and the run over WinRM (§10, A-0025) as one session under
`lab/windows/bin/with-dc1-lock` (upload with the `DC.put` helper of `agent-verify`, which checks the sha256),
running in elevated PowerShell on dc1:
`powershell -ExecutionPolicy Bypass -File C:\lab\agent-harness\Install-AgentLabHarness.ps1`
Evidence (sc qc/qprivs/qsidtype, `whoami /priv|/user|/groups` as the service, data-dir SDDL, OS build) goes to
`C:\lab\agent-harness-evidence`; copy it to `windows-lab-runs/agent-harness-<UTC>/`. Exit 0 = every check
passed. Remove with `-Uninstall` (service, key and data dir) before releasing the lock. Offline guard: `make lab-test-windows-unit`.

Status: **not yet run on dc1** (it was written before VM 119 and WinRM access existed). Things to
watch on the first run: the restricted SID type adds restricting SIDs, so the stub's read of
`System32\whoami.exe` or the binary directory may need an ACE for the service SID. Record what fails; that is
an input to the MSI design and the A3 fitness item of ADR-0006.


## 13. DC agent MSI verification (T-0648)

Builds the agent MSI with WiX on the lab DC and runs the ADR-0006 cases against it: install, restricted
token, Security channel ACE and read, GPO reset and re-grant, corrupt `agent.json`, repair, forced failed
major upgrade, `agentsetup` refusals, `CheckDataDir`, `EvtLogOldestRecordNumber`, uninstall cleanliness.

```bash
pip install pywinrm requests-ntlm                      # operator tooling; licence register row
export WIN_LAB_ENV=<path to the main checkout's lab/windows/.win-lab.env>   # gitignored; DC address defaults to 192.168.1.9
export WIN_LAB_DC_ADDR=<dc ip>                         # optional override
lab/windows/bin/agent-verify --log knowledge/development/runbooks/windows-lab-runs/T-0648-agent-<date>.log
```

- **The whole run holds the dc1 lock** (§10): `agent-verify` re-executes itself under
  `lab/windows/bin/with-dc1-lock`, so a second run queues (it prints the holder) instead of colliding.
  The log's first line records it: `dc1 lock held by pid … for the whole run, waited …s`. Other dc1
  work must wait for it to finish; it can take up to 30 minutes.

- It cross-builds `activediq-agent.exe`, `agentsetup.exe` and the `windowslab` Go tests, copies them and
  `Agent.wxs` to `C:\lab\build` over WinRM (HTTP 5985, NTLM, lab network), installs the .NET 8 SDK and WiX
  5.0.2 to `C:\lab\tools` on first use (the DC needs internet; nothing is installed system-wide), builds the
  MSI there, and runs `lab/windows/guest/agent-verify.ps1`. Exit status is the number of failed cases.
- **It installs, upgrades and removes the agent and clears the Security log. Lab DC only.** It leaves the
  DC with the agent uninstalled and `ProgramData\skenzeriq` removed. The lab user it creates for two cases
  has a per-run random password that is never printed, and is deleted at the end.
- Reading the service token needs no enrolment: the script points the service image at a 25 s stub for
  a few seconds (SCM builds the token from the service configuration, not the binary), reads that process's
  token with `OpenProcessToken`, and restores `ImagePath`. If a run dies in that window, check
  `HKLM\SYSTEM\CurrentControlSet\Services\activeDIQAgent\ImagePath` is the quoted `activediq-agent.exe` path.
- If a run leaves the DC odd, re-run (the script is idempotent) or clean up over WinRM; `qm rollback <vmid> clean`
  needs the Proxmox host (no worker access: raise an `action new`).
- Not covered (needs an enrolled agent talking to a server; T-0814): killing the server connection,
  filling the data disk, and the U+0001 `Data` value reaching the server.

## 14. Searching VM 119 through the server (T-0669)

A server built with `-tags lab` and started with the `WIN_LAB_*` variables of section 10 seeds an active
connection to VM 119 (lab bootstrap, T-0684) and answers `GET /api/v1/directory/users?q=lab-user-01`
through `client.UserSearch` -> in-process connector -> LDAPS as `svc-activediq`. The service account must
pass the rights check (no Tier-0 group); otherwise the answer is 503 `directory_unavailable` with a fixed
reason. The ScopedSearch lab test is `internal/connector/read/search_lab_test.go` (`-tags lab`). The
Windows run with signing and channel binding enforced on dc1 is T-0671; it was not run from the T-0669
session (VM 119 unreachable).

## 15. SASL GSSAPI + channel binding proof (T-0566)

`kerberos_windows_lab_test.go` (`-tags 'lab windowslab'`) is the Windows twin of the Samba `kerberos_lab_test.go`
(T-0560). It needs dc1 enforcing **LDAP signing required** (`LDAPServerIntegrity=2`) and **channel binding always**
(`LdapEnforceChannelBindingTokens=2`, read at boot), plus a keytab identity. `lab/windows/bin/gssapi-lab` drives it over WinRM
(5985, NTLM, lab only; `pip install pywinrm requests-ntlm`; wrap every call in `flock -w 3600 /tmp/claude-1000/activediq-dc1.lock`):

1. `export WIN_LAB_ENV=<main checkout>/lab/windows/.win-lab.env WIN_LAB_CA=<main checkout>/lab/windows/.win-lab-ca.pem`, then
   `gssapi-lab prepare` (once per DC): runs `guest/gssapi-ready.ps1` on dc1 (both registry values, AES-only account
   `svc-t0566-gssapi` with an AES256 `ktpass` keytab, AES-only gMSA `gmsa-t0566$` readable by Administrator and the DC), copies
   `svc.keytab` and `gmsa.json` to `.win-lab-gssapi.keytab` and `.win-lab-gmsa.json` beside the env file (gitignored, 0600;
   override with `WIN_LAB_GSSAPI_KEYTAB`, `WIN_LAB_GMSA`), deletes them on the VM and reboots dc1.
2. `gssapi-lab run [go test args]` (default: the whole suite). It puts dc1's clock in step with the host for the run
   (**dc1 is +12h30m, bug T-0850; Kerberos allows 5 min**), turns on `16 LDAP Interface Events`=2 so the DC logs event 3039, runs
   `go test`, prints the DC's channel-binding events and restores the clock offset and the diagnostics value in a `finally`.
   Do not run the Go tests against dc1 without it: they fail with KRB_AP_ERR_SKEW.

| Test | Pins |
| --- | --- |
| `…KeytabBindWithChannelBinding` | keytab identity binds over verified LDAPS, SPN `ldap/<fqdn>`, layer none, whoami + rootDSE work |
| `…GMSAKeytabBind` | keytab derived from the gMSA managed password binds (derivation confirmed) |
| `…WrongChannelBindingRejected` | control with the DC's own cert binds; a binding of another cert is refused with ldap 49 and logged as event 3039 |
| `…MissingChannelBindingRefusedClientSide` | no request without a binding (the server-side "absent" case cannot be produced by this client) |
| `…WrongSPNFails`, `…BadKeytabFailsBind` | each has a control with the real SPN / key that binds; SPN for another host and a foreign key are refused |
| `…OpenKeytabBind`, `…OpenGMSABind` | the same binds through `ad.Open`. **Red on purpose until bug T-0846** (go-krb5 rejects the WS2025 AS-REP, PA-REQ-ENC-PA-REP) |

All other tests drive the handshake with `client.DisablePAFXFAST(true)` so the DC-side behaviour is pinned independently of T-0846.
Run log, dc1 before/after state and the broken-run proof: `windows-lab-runs/T-0566-gssapi-2026-10-30.md`.
`LdapEnforceChannelBindingTokens` is not re-read at runtime (setting 0 left enforcement on), so the "CBT off accepts a wrong binding"
proof needs a reboot cycle and was not run. The test accounts stay on dc1 for the T-0846 fix; remove with `Remove-ADUser svc-t0566-gssapi`
and `Remove-ADServiceAccount gmsa-t0566`.

## 16. Child domain (dc2) (T-1233, for T-0786 / T-1234)

Why: T-0786 (GC-routed sIDHistory) needs the global catalog to hold more than one domain's SIDs, so the forest
needs a child domain. This section is the **human** procedure: a second DC is a second Proxmox VM and A-0025 covers
`dc1` only (§10), so workers never touch dc2. They verify afterwards through dc1 (T-1234). The kit is
`lab/windows/guest/child-dc-init.ps1` + `child-dc.ps1` (via `boot.ps1`, role `child-dc`), built on `common.ps1`.

| Thing | Value |
| --- | --- |
| New domain | `child.win.activediq.test`, NetBIOS `WINCHILD`, child of `win.activediq.test` (dc1, `WINLAB`) |
| Promotion | `Install-ADDSDomain -DomainType ChildDomain -CreateDnsDelegation -InstallDns -NoGlobalCatalog` (dc1 stays the only GC and holds the child's partial NC; T-0786 keeps dialling `dc1:3269`) |
| VM | Windows Server 2025 **Evaluation**, 2 vCPU, 4 GiB RAM, 60 GB disk, one NIC on dc1's network (a fresh install; do not clone dc1) |
| Host name / IP / DNS | `DC2`; a static IP on dc1's subnet (`<DC2_IP>`, a free address; same prefix and gateway as dc1); **DNS = dc1 only** (`<DC1_IP>`), never itself or a public resolver |
| Secrets | You type the parent `WINLAB\Administrator` password once, at a hidden prompt (SecureString). It is never in argv, a file, a log or a note. The DSRM password is generated on dc2 into `C:\lab\dsrm-password.txt`, readable by SYSTEM and Administrators only |

**Steps (human, on the new VM unless stated)**

1. **Create the VM** in Proxmox from the same WS2025 evaluation ISO as dc1 (spec above). Log in as the local `Administrator`.
2. **Name and network** (elevated PowerShell; check the alias with `Get-NetAdapter`):
   `Rename-Computer -NewName DC2 -Restart`, then
   `New-NetIPAddress -InterfaceAlias Ethernet -IPAddress <DC2_IP> -PrefixLength 24 -DefaultGateway <GATEWAY>` and
   `Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses <DC1_IP>`.
3. **Copy the guest scripts**: `lab/windows/guest/*.ps1` from the repo to the VM, e.g. `C:\guest\`.
4. **Check and stage:** `powershell -ExecutionPolicy Bypass -File C:\guest\child-dc-init.ps1 -ParentDcIp <DC1_IP> -Dc2Ip <DC2_IP>`.
   It refuses unless the name is `DC2`, the IP is configured, DNS includes dc1 and dc1 resolves the forest's locator
   records. It writes `C:\lab` with the scripts and a `lab.json` that holds **no secret**.
5. **Provision:** in an elevated console (not a scheduled task) run `powershell -ExecutionPolicy Bypass -File C:\lab\boot.ps1`.
   It installs the roles (rebooting once if Windows asks; the `LabResume` task then waits and logs "waiting for a
   human"), so after that reboot run the same `boot.ps1` again at a console. It prompts for the parent
   Administrator password, generates the DSRM password, promotes (reboots by itself) and finishes through
   `LabResume`. Done when `C:\lab\provision.log` ends with `dc2 provisioned`. A failed stage logs `FAILED stage=…`
   there and re-runs at the next start; if promotion was refused, fix the cause and run `boot.ps1` again (the DSRM
   file is reused).
6. **Keep the DSRM password:** `scp` `C:\lab\dsrm-password.txt` to the lab host (mode 0600, never email or chat),
   then delete it from dc2. Do not paste it anywhere.
7. **Evidence** (paste the output into the CEO action / T-1234; none of these prints a secret):
   - on dc1 and on dc2: `(Get-ADForest).Domains` and `(Get-ADForest).GlobalCatalogs` (expect both domains; dc1 is the GC);
   - on dc1 and on dc2: `nltest /dclist:child.win.activediq.test` and `nltest /dclist:win.activediq.test`;
   - on dc1 and on dc2: `repadmin /replsummary` (expect 0 failures, 0 errors) and, on dc1, `repadmin /showrepl` showing the
     `DC=child,DC=win,DC=activediq,DC=test` partial replica;
   - on dc1: `Resolve-DnsName child.win.activediq.test -Type NS` (the delegation).
8. **Snapshot `clean`** (Proxmox host, dc2 shut down): `qm shutdown <DC2_VMID> && qm snapshot <DC2_VMID> clean --description "clean provisioned child DC" && qm start <DC2_VMID>`.
   Revert later with `qm rollback <DC2_VMID> clean`. Note the build date: the evaluation licence is 180 days (§4); **rebuild, don't rearm**.
   If dc1 is rolled back to its own `clean`, dc2 must be rolled back too (their replication partnership must agree), and vice versa.

**Rebuild or abort.** Not promoted yet: delete `C:\lab` and start at step 4. Half-promoted or wrong: rebuild the VM
(step 1), and tidy dc1 afterwards (`ntdsutil` metadata cleanup of the stale child domain and the DNS delegation) as a
human; workers do not do that over WinRM.

**Then:** the worker ticket T-1234 verifies through dc1 only (`DomainSIDs` >= 2, the child's partial NC on dc1) and then T-0786 runs.
