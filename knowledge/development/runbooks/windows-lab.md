---
title: "Runbook: the Windows Server 2025 lab (local KVM, evaluation licence)"
date: 2026-10-23
updated: 2026-11-03
status: draft
owner: devops-engineer
ticket: T-0254
---

# Runbook: the Windows Server 2025 lab

The lab for everything Samba cannot prove (Windows event logs, GPO/audit policy, NTLM events, real
LDAPS/WS2025 hardening behaviour, ADWS, native components — see `ad-lab.md` §6). Chosen in D-0003
(option a): **local evaluation VMs on KVM, free**. In the local-KVM mode, a DC (`dc1`) and a member/file server
(`fs1`) in a throwaway forest; the live lab (§10) is `dc1` on Proxmox VM 119 plus, once a human has built it,
a child-domain DC `dc2` (§20). Code: `lab/windows/`. Samba stays the default lab (`ad-lab.md`); use this one only
for tests tagged `windowslab`.

## 1. Quick start

Host needs: Linux x86-64 with `/dev/kvm`, ~45 GB free (thin-provisioned qcow2, ≈15 GB real use per VM
plus the 5 GB ISO), 8 GB spare RAM, and
`sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients virtinst ovmf xorriso netcat-openbsd`
(your user in groups `libvirt` and `kvm`). Apple Silicon cannot run this lab.
`preflight` refuses below that floor; `WIN_LAB_MIN_FREE_GB` (default 45) overrides it and exists only so the offline unit
tests (`lab/windows/tests/`) do not depend on the CI host's free disk — never lower it for a real `up`.

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

**The DC address has no default (T-1279).** `agent-verify`, `agent-unenrolled-verify` and `gssapi-lab` need
`WIN_LAB_DC_ADDR` (dc1's current IP or host name) in the environment or in the lab env file, and exit non-zero
naming the key — before the lock, a build or any connection — when it is missing, empty or not a plain
IP/host name (`lab/windows/lib/labaddr.py`). dc1 has changed address before (A-0032), and a baked-in fallback
would aim these drivers, which reboot the DC and clear its logs, at whichever LAN device holds the old address.
Before a run, confirm the address is dc1: `ip neigh show <ip>` should show the VM's MAC (prefix `bc:24:11`).
`lab/windows/tests/test_dc_addr_required.py` fails if a driver regains a default or the old address returns.

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
dc1 session. Once the CEO has run the pool bootstrap below, workers do those themselves with
`lab/proxmox/bin/proxmox-lab` (only on VMs in the `adiq-lab` pool); until then, or if the token was revoked,
raise an `action new` for a rollback. Everything that runs *inside* dc1 is done by workers over WinRM.

**dc2 (child domain) is human-only.** A-0025 covers `dc1` only: no worker may open WinRM, PowerShell remoting or
any other session to `dc2` (VM, address or name), and the `with-dc1-lock` wrapper is not a licence to. In short,
every step inside dc2 is done by a human (§20); workers verify the child domain only through dc1 (T-1234). Extending the
authorisation to dc2 is a CEO decision, not a ticket step.

**fs1 does not exist.** There is no member server in this lab: only dc1 (VM 119). The `fs1` rows in §1–§2
describe the local-KVM mode, which was dropped. A human creates fs1 (A-0028; tickets T-0409, T-0413).
Until then no worker step may assume `fs1`, and proofs that need a member server stay blocked on A-0028.

**dc1 changes that a rollback of dc1 would undo (T-1734, 2026-11-07).** `Update-LapsADSchema` was run on dc1: the lab forest now has the
Windows LAPS schema (`msLAPS-*` attributes, the `ms-LAPS-Encrypted-Password-Attributes` extended right, `mayContain` on `computer`); it was absent
before, although the forest is level 2025. A schema extension cannot be removed; a rollback to an older snapshot removes it, and a LAPS test written
against dc1 should call `Update-LapsADSchema` (idempotent) first. The `t1734-*` objects the run deleted stay in `CN=Deleted Objects` until they expire.
`CN=Deleted Objects` is back to its default descriptor (owner SYSTEM): by default not even a Domain Admin can read it, see
`knowledge/development/domain/deleted-object-read-access.md`.

### Proxmox lab pool (D-0022)

**Decision.** The CEO answered D-0022 (a) on 2026-11-02: workers get a Proxmox API token that can reach only
a resource pool called `adiq-lab`, so they build, snapshot and roll back lab VMs (dc1, fs1, a Win11 client,
dc2) themselves. Code: `lab/proxmox/` (`bin/proxmox-lab-bootstrap`, `bin/proxmox-lab`, `lib/pvelab.py`).
Python standard library, `ssh` and nothing else; no dependency was added.

**Bootstrap: the CEO runs one command, once.** From the factory host's main checkout (needs Proxmox VE 8 or
newer, and that you can log in to the Proxmox host as root over ssh):

```bash
make proxmox-lab-bootstrap PVE_HOST=<proxmox address>
```

ssh asks for your own root login on your terminal, and for the host-key confirmation the first time. Type it
there; it is never given to a script, a file or a ticket. To read every command before it runs, add
`ARGS=--dry-run` (nothing is contacted). If VM 119 has disks on more than one storage, or the VM's net0 has no
bridge, the command stops and says which of `ARGS="--storage S"`, `--bridge B`, `--iso-storage S` to add.

What it does, over that one ssh connection (each command is an argument list, quoted, with every value
checked against a strict pattern first):

| Step | Command (on the Proxmox host) |
| --- | --- |
| Discover | `pveversion`; `pvesh get` of the VM list, VM 119's config (its disk storage and net0 bridge), `/storage`, the node's certificate list. Read-only |
| Pin the API certificate | takes the SHA-256 fingerprint of `pveproxy-ssl.pem` (else `pve-ssl.pem`) read over ssh, then checks the API at `PVE_HOST:8006` serves that same certificate; a mismatch stops everything before any change |
| Pool | `pveum pool add adiq-lab`; `pveum pool modify adiq-lab --vms 119` |
| Role | `pveum role add AdiqLabWorker --privs …` (the exact list is `WORKER_PRIVS` in `lab/proxmox/lib/pvelab.py`) |
| User and token | `pveum user add adiq-lab@pve` (no password, so it cannot log in); `pveum user token add adiq-lab@pve worker --privsep 1` |
| ACLs | `pveum acl modify` on exactly `/pool/adiq-lab`, `/storage/<lab storage>`, `/sdn/zones/localnetwork/<dc1's bridge>`, each for the user and the token (a privilege-separated token holds the intersection of both). If ISO images live on a different storage, that one storage gets the read-only role `AdiqLabIso` (`Datastore.Audit`) |
| Reconcile | any other ACL held by `adiq-lab@pve` or its token (for example left by an earlier run) is deleted |
| Handover | writes `lab/.proxmox-lab.env` (host, port, node, token id, **secret**, pinned fingerprint, pool, storage, bridge) with mode 0600, git-ignored; the secret goes from the ssh channel into that file and is not printed, put in argv, or logged |
| Verify | runs `proxmox-lab verify-scope` with the new file; if it fails the script says so and exits non-zero. Revoke, then raise a ticket |

Running it again is safe: with a matching env file it keeps the token; `ARGS=--rotate` replaces the token and
file; if the file is lost the token is replaced.

**What the token can and cannot do.** Can, on VMs in `adiq-lab` only: create (new VMs are always created in the
pool), start, stop, snapshot, roll back, attach or eject an ISO, read config and console, allocate disks on the
lab storage, and use dc1's bridge. Cannot: see or touch any VM outside the pool (workers cannot even list
them; the driver reads pool membership from `GET /pools?poolid=adiq-lab`, which needs only `VM.Audit` on the members, because
`GET /pools/adiq-lab` would need `Pool.Audit`), anything `Sys.*` (no node shell, no network, no certificates), `Permissions.*`, `User.*`, `Pool.*`,
`Realm.*`, `Group.*`, change any ACL, create users or tokens, migrate, clone, back up, delete a datastore
or reach the QEMU monitor (`VM.Monitor` is not granted). It holds no ACL on `/` or `/vms`. Note the role does
include `VM.Allocate` (create and destroy VMs) and `Datastore.AllocateSpace` on the lab storage: a worker can
destroy and fill VMs in the pool; that is why recovery is below, and why dc1 is snapshotted before risky work.

**Worker driver.** `lab/proxmox/bin/proxmox-lab` (finds `lab/.proxmox-lab.env` in this checkout or the main
checkout; or set `PROXMOX_LAB_ENV`). A worktree has no gitignored files, so the main checkout's file is used.

```bash
proxmox-lab list                                     # VMID, name, status of the pool's VMs
proxmox-lab snapshot 119 before-agent-install       # recovery points: take one before anything risky
proxmox-lab rollback 119 before-agent-install
proxmox-lab start 119 | stop 119 [--graceful] | snapshots 119
proxmox-lab attach-iso 119 local:iso/win11.iso      # or: attach-iso 119 --eject
proxmox-lab create --name fs1 --vmid 120 --iso local:iso/ws2025.iso [--memory-mb 8192 --cores 4 --disk-gb 60 --uefi-tpm]
proxmox-lab verify-scope                             # exit 1 unless the token is exactly the lab token
```

Every subcommand that names a VMID first reads the pool and refuses (exit 2) any VMID that is not a member,
before it makes a call for that VM. `verify-scope` fails closed: it fails if the token can see any VM outside
the pool, any other pool, holds any privilege outside the role (and names `Sys.`/`Permissions.`/`User.` ones
specially), holds privileges on any path other than the pool, its VMs, the lab storage(s) and the bridge, if
dc1 is missing from the pool, or if any call errors. Run it at the start of a lab session. Each call checks
the API certificate's fingerprint after the TLS handshake and before sending the token; a mismatch sends nothing
(no `-k`, no insecure mode). Wrap dc1 sessions in `with-dc1-lock` as before; the driver does not take the lock
for you, so do not roll dc1 back while another session holds it.

**Revoke: the CEO runs one command.**

```bash
make proxmox-lab-revoke PVE_HOST=<proxmox address>      # ARGS=--dry-run to read the commands first
```

It deletes every ACL held by the user or the token (read from `pvesh get /access/acl`), the token, the user
`adiq-lab@pve`, the roles `AdiqLabWorker` and `AdiqLabIso`, and the local `lab/.proxmox-lab.env`, then checks
nothing is left. It issues no command that addresses a VM and does not change the pool: every VM, including
those in `adiq-lab`, keeps running or stopped as it was, with its snapshots. The empty-of-access pool stays;
delete it in the Proxmox UI if you wish. Revoke also when a worker machine is lost or a secret may have leaked,
then bootstrap again for a new token.

**Recovery = snapshot rollback.** A worker that breaks dc1 (or any pool VM) runs `proxmox-lab rollback <vmid>
<snapshot>` under `with-dc1-lock`. **dc1's rollback target is `clean-signing-2026-11-02`** (taken 2026-11-04 with dc1 at
`LDAPServerIntegrity`=2 and `LdapEnforceChannelBindingTokens`=2, T-1327). The older snapshot `clean` (2026-10-28, LDAP signing
negotiated) is **superseded**: kept, not deleted, never the rollback target. Disk-only snapshots roll back to a stopped VM:
`proxmox-lab start 119`, wait for NTDS, then run `dc1-policy check` (and `restore` if it fails). `VM.Snapshot` also lets the token
delete snapshots, so keep a second snapshot name before rolling back over the only one. For another pool VM with no clean snapshot, the
first worker session takes one before changing anything. If the token itself is suspect, the CEO revokes (above); VMs are unaffected.

**Proof.** `make proxmox-lab-test` (offline, in `make ci` through `lab-test-unit`) runs the real scripts against
a fake `ssh`/`pveum`/`pvesh` and a stub HTTPS API: scope refusals, `verify-scope` failures (outside VM, `Sys.`,
`Permissions.`, `User.`, ACL on `/` and `/vms`, extra privilege, other pool, API error), TLS fingerprint mismatch
sending no request, the secret absent from stdout, stderr, argv and logs, env file mode 0600, and revoke leaving
every VM untouched. It was first run against the real host in T-1327 (`windows-lab-runs/T-1327-proxmox-pool-scope-20261104.md`), which found
that the real API sends no `pool` field in `/cluster/resources` for the token; membership is now read from `GET /pools?poolid=adiq-lab`.

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
Reset = `qm rollback <vmid> clean` on the Proxmox host (VM 119 for the first build; for dc1 workers now use `proxmox-lab rollback 119 clean-signing-2026-11-02`, see Recovery above). Certificate verification is never disabled: the Go tests dial
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
no RODC; the child domain exists only after §20 is done): RODC corroboration, cross-domain GPO links, gPLink option/order edge cases, >1500-member ranged groups
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
  a rollback is `proxmox-lab rollback 119 clean-signing-2026-11-02` (under the lock, then `dc1-policy check`); raise an `action new` only if the token is revoked.

**Judge it on the repo host** (copy `obs.json` back, one per host: `obs-dc1.json`, `obs-fs1.json`):

```bash
go run ./tools/fitness/host evaluate obs-dc1.json
go run ./tools/fitness/host evaluate obs-fs1.json
```

Then add `windows-lab-runs/T-0635-msi-refuses-dc-<date>.md` with both sha256s, both `obs.json`, the
`msi.log` line holding the DC message, and the evaluate output. `tools/fitness/host` is on `factory/T-0635`
until that branch merges. Status: run on dc1 on 2026-10-30 (T-0635): exit 1603, DC message, nothing installed, HOST-DC-REFUSED ok; see
`windows-lab-runs/T-0635-msi-refuses-dc-20261030.md`. fs1 (the install control) has not been run, so the MSI has
never installed on a host. Workers reach dc1 over WinRM (A-0025, section 10) under `lab/windows/bin/with-dc1-lock`; fs1 (A-0028) is still to come.

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
export WIN_LAB_ENV=<path to the main checkout's lab/windows/.win-lab.env>   # gitignored
export WIN_LAB_DC_ADDR=<dc ip>                         # REQUIRED unless it is set in that env file; no default
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
- **T-0557 variant** `agent-verify --guest agent-t0557.ps1 [--mode gpo-restart]`: same build, then a real GPO
  (`New-GPO`/`New-GPLink` on the Domain Controllers OU, removed at the end), refusal of an elevated administrator
  token, job-limit read-back, CPU-cap measurement, a logon-load run and a 10-minute backlog read. About 35 minutes;
  `--mode gpo-restart` restarts the Event Log service (a real GPO takes effect only then). Results:
  [domain note](../domain/dc-agent-channel-acl-gpo-and-bounds.md). Re-run `dc1-policy check` afterwards (section 18).
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
2. `gssapi-lab run [go test args]` (default: the whole suite). It reads dc1's clock and refuses to run if it is more than 60 s
   from this host (the clock is fixed, section 16; the script never steps it), turns on `16 LDAP Interface Events`=2 so the DC logs
   event 3039, runs `go test`, prints the DC's channel-binding events and restores the diagnostics value in a `finally`.

| Test | Pins |
| --- | --- |
| `…KeytabBindWithChannelBinding` | keytab identity binds over verified LDAPS, SPN `ldap/<fqdn>`, layer none, whoami + rootDSE work |
| `…GMSAKeytabBind` | keytab derived from the gMSA managed password binds (derivation confirmed) |
| `…WrongChannelBindingRejected` | control with the DC's own cert binds; a binding of another cert is refused with ldap 49 and logged as event 3039 |
| `…MissingChannelBindingRefusedClientSide` | no request without a binding (the server-side "absent" case cannot be produced by this client) |
| `…WrongSPNFails`, `…BadKeytabFailsBind` | each has a control with the real SPN / key that binds; SPN for another host and a foreign key are refused |
| `…OpenKeytabBind`, `…OpenGMSABind` | the same binds through `ad.Open`. Were red until bug T-0846 (go-krb5 rejects the WS2025 AS-REP, PA-REQ-ENC-PA-REP); the connector now builds its client with `client.DisablePAFXFAST(true)` (`newKerberosClient`), so they must pass on dc1. |

All other tests drive the handshake with `client.DisablePAFXFAST(true)` so the DC-side behaviour is pinned independently of the Open path. `TestKerberosClientOmitsPAReqEncPARep` (no lab) pins that the product client never sends PA-REQ-ENC-PA-REP.
Run log, dc1 before/after state and the broken-run proof: `windows-lab-runs/T-0566-gssapi-2026-10-30.md`.
`LdapEnforceChannelBindingTokens` is not re-read at runtime (setting 0 left enforcement on), so the "CBT off accepts a wrong binding"
proof needs a reboot cycle and was not run. The test accounts stay on dc1 for the T-0846 fix; remove with `Remove-ADUser svc-t0566-gssapi`
and `Remove-ADServiceAccount gmsa-t0566`.

## 16. dc1 clock and time source (T-0850)

**What was wrong.** dc1 (the PDC emulator) ran on `Local CMOS Clock` (`Type: NT5DS`, no peer) and its clock sat about 12h30m
ahead of real time (13h30m after the 2026-11-01 DST change: the offset followed the local time zone, Pacific, so it is a
wall-clock/RTC mismatch in the VM, not a drift). The KDC refused every AS-REQ from this host with `KRB_AP_ERR_SKEW` (37);
Kerberos allows 5 minutes. T-0566 worked round it by stepping the clock for each run; that is gone.

**Fix (done 2026-11-01, over WinRM, no Proxmox access needed).** dc1 syncs from external NTP peers (Cloudflare's time service, 162.159.200.1 and .123, <https://www.cloudflare.com/time/>), by IP address because dc1 is its own DNS and a name does not resolve at boot (w32time then waits 15 minutes and doubling before it retries; seen in the first reboot test), so the clock is right
after every boot whatever the VM's RTC says:

```powershell
w32tm /config /syncfromflags:manual /manualpeerlist:"162.159.200.1,0x8 162.159.200.123,0x8" /reliable:yes /update
Restart-Service w32time; w32tm /resync /rediscover
```

Time zone is unchanged (Pacific Standard Time); only UTC matters to Kerberos, TLS and the tests.

**Operate it.** `lab/windows/bin/dc1-clock check [--max-skew S]` prints dc1 minus host and the w32time source and exits 1 over the
limit (default 1 s). `dc1-clock fix` re-applies the config above (idempotent; the clock step drops the WinRM session, so it
waits and re-checks). Peer override: `DIQ_DC1_NTP_PEER`. Wrap in `with-dc1-lock` like every dc1 session (section 10).
Proof the check can fail: `dc1-clock check --max-skew 0.0001` exits 1 against a correct clock.
Offline tests (fake DC, no WinRM): `python3 lab/windows/tests/test_dc1_clock.py` runs `check` (in step, 12h30m skew, strict limit)
and `fix` (to the `after:` line, session cut, clock stuck); it fails if `dc1-clock` loses an import.

**Needs.** dc1 reaches the NTP peer on UDP 123 (the lab network has outbound internet). If that ever stops, `check` fails and
Kerberos tests fail again; use a lab-local NTP server (`DIQ_DC1_NTP_PEER`) rather than stepping the clock by hand.

**Side effects of the one-time step back (13h30m).** Objects and events written while the clock was ahead carry timestamps in
the future (for example the domain object's `whenChanged` 2026-11-02, Security/System events of 2026-10-27..11-02 dc-time). They
are not rewritten. Tests that order or window by event time on dc1 must use events created after 2026-11-01T15:11Z, or filter by
content. The lab CA and DC certificates (`NotBefore` 2026-10-27T12:1xZ) are before real time, so TLS validity is unaffected.
If a Proxmox owner wants the root cause too: check VM 119's `localtime`/`startdate` options (`qm config 119`); Windows expects a
local-time RTC unless `RealTimeIsUniversal=1`. Not needed while NTP sync is on.

## 17. Unenrolled-start and start-after-enrol proof for the DC agent (T-0833, for T-0813)

`lab/windows/bin/agent-unenrolled-verify --log knowledge/development/runbooks/windows-lab-runs/T-0833-agent-unenrolled-<date>.log [--trials 3] [--ref HEAD]`
re-runs the whole proof. Run it from a worktree with `WIN_LAB_ENV=<main checkout>/lab/windows/.win-lab.env`; it re-executes itself
under `with-dc1-lock` (§10), takes 6-8 minutes, and restores dc1 (agent uninstalled, `C:\Program Files\skenzeriq` and
`C:\ProgramData\skenzeriq` removed; the log records a before and an after snapshot that must match). A killed run still restores
(SIGTERM handler); if the log has no AFTER block, run it again, its first step is the same restore.

| Check | What it does on dc1 | Failing fixture |
| --- | --- | --- |
| AC1 | builds `Agent.wxs` of `--ref` (a throwaway worktree) with WiX 5.0.2 as `wix build -wx -sw1149`: exit 0, no `WIX0004`, no `WIX1149`, no warning of any kind (`-wx` makes an unsuppressed warning an error) | the same file without `-sw1149` must fail with `WIX1149`; a failure-action attribute on the core `ServiceConfig` must fail with `WIX0004` |
| AC2 | `msiexec /i` while unenrolled with `Start=install`: exit 0, no `1920` in the log, service Running, same PID after 45 s (past the 30 s recovery delay), no SCM 7031/7034/7024/7023/7009/7000, no event 101, `sc qfailure` read back | none needed: each assertion is a different observable (a non-zero exit, a `1920` line, a PID change or an SCM failure event each fail it) |
| AC3 | event 103 of source `activeDIQ Agent`: `Get-WinEvent` message and the `wevtutil /f:text` rendering that Event Viewer shows must contain the text and not `cannot be found`; registered message file printed | an event written under a source key with no message file renders `Description: N/A`, and the same predicate rejects it |
| AC4 | (T-1249 adds three ACL checks per trial: every enrolment path grants `NT SERVICE\activeDIQAgent`, is owned by `BUILTIN\Administrators`, and does not name the enrolling administrator.) `enrol-stub` (this host, `lab/windows/enrol-stub`, throwaway pinned CA and tenant CA, prints PIN/TOKEN, logs `ENROLL ok` and `TUNNEL mTLS client verified` with host-clock timestamps) is the fleet server; `activediq-agent.exe enroll <host:7443> <pin>` runs on dc1 with the token on stdin (uploaded to a file the script deletes at once); pickup is the first verified mTLS connection from the same service PID, latency = stub's TUNNEL minus ENROLL time | no connection within 40 s fails; the stub is single-use and refuses a wrong pin (`go test ./lab/windows/enrol-stub`, part of `make lab-test-windows-unit`) |
| AC5 (T-1249) | enrol, then add a `BUILTIN\Users` ACE to the enrolment directory and start the service: after 20 s event 104 (Error) exists and names `unsafe-permissions`, event 103 does not, the service is Running and the same process | no event 104 fails it; a 103 for state that exists fails it |

T-1249 removed the "repaired lab variant" (it is now the committed file) and the DIAG step (cause 1 is fixed in `dial`).

**Result of the first run (2026-11-01, `factory/T-0813` merged with `main`): AC1 FAIL, AC2 PASS, AC3 PASS, AC4 FAIL.** Details and the
analysis are in the log and in bug T-1249: the committed `Agent.wxs` does not build (WIX0004; the core `ServiceConfig` has no failure-action
attributes and is itself the source of WIX1149), and an administrator's `enroll` writes a DACL that the service identity refuses, which
the T-0813 idle loop turns into a silent permanent idle. Needs on the lab host: the Go toolchain, `pip install pywinrm requests-ntlm`, and
dc1 reaching this host on TCP 7443 (`--port`). No new tool or dependency (WiX 5.0.2 and pywinrm are already in the licence register;
the stub uses gRPC already in `go.mod`).

## 18. dc1 must stay at LDAP signing required + channel binding always (T-1265)

Every Windows-lab proof that claims "signing and channel binding enforced" (the GSSAPI suite of section 15, the walking
skeleton T-0671, the channel-binding acceptance T-0148) is only true while dc1 reads
`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` **`LDAPServerIntegrity` = 2** and **`LdapEnforceChannelBindingTokens` = 2**.
On 2026-11-01 dc1 read `LDAPServerIntegrity` = 1 (negotiated) with CBT still 2, and a cleartext simple bind answered 49
instead of 8. Nothing in the proofs noticed.

| Tool | What it does for this policy |
| --- | --- |
| `lab/windows/bin/dc1-policy check` | Read-only. Reads both values over WinRM and reads the Default Domain Controllers Policy template, and does a cleartext simple bind to 389 **as `svc-activediq`** (password from `WIN_LAB_SVC_PASSWORD`, never printed). Exit 0 only when both values and the GPO are 2 **and** the bind answers 8 (strongerAuthRequired); else exit 3 and names each value it read. |
| `lab/windows/bin/dc1-policy restore` | Writes both values to 2 when they are not (the table is `lib/dc1policy.py` `REQUIRED`; nothing else can be written), reboots dc1 (CBT is read at boot) and waits for NTDS, then runs `check`. Does nothing, and does not reboot, when dc1 is already 2/2. |
| `lab/windows/bin/gssapi-lab run` | Runs `check`-equivalent first and stops **before** any change on dc1 or any `go test`, naming the value read. After the run (in the `finally`) it reads again and fails the run if the policy moved. |
| `lab/windows/bin/gssapi-lab prepare` | Same check after the reboot; `guest/gssapi-ready.ps1` writes 2/2 first and asserts 2/2 in a `finally`, so a failure half-way (ktpass, gMSA) cannot leave a lower value. |
| any new proof that needs the policy | Call `with-dc1-lock lab/windows/bin/dc1-policy check` as its first step and stop on non-zero (`lab/e2e/run-skeleton-proof.sh windows`: T-0671 adds the call; see the T-1265 advance note). |

Always under the lock: `lab/windows/bin/with-dc1-lock lab/windows/bin/dc1-policy restore` (or `flock -w 3600 /tmp/claude-1000/activediq-dc1.lock …`).
Needs `pip install pywinrm requests-ntlm` and `WIN_LAB_ENV`; WinRM on dc1 is lab-only (A-0025).

**Rules for lab scripts.** No script may write `LDAPServerIntegrity` or `LdapEnforceChannelBindingTokens` to anything but 2, and none may
"restore a captured before-value" for them. `lab/windows/tests/test_dc1_policy.py` scans `lab/` for writes and fails on any other value;
`make lab-test-windows-unit` runs it. A snapshot rollback (`proxmox-lab rollback`; before A-0038 a human `qm rollback`) puts back whatever the snapshot held:
after any rollback or restore of VM 119 run `dc1-policy restore` before the next proof.

**Offline tests.** `python3 -m unittest lab/windows/tests/test_dc1_policy.py`: a fake DC at 1/2, 2/1, absent and a drifting DC prove `gssapi-lab run`
refuses or fails; a bad-fixture scan proves a script writing 1 or 0 is caught; a fake LDAP port proves the bind probe tells 8 from 49.

**Why registry-only restores do not last (T-1265 root cause).** The Default Domain Controllers Policy template (`GptTmpl.inf` in
SYSVOL, GUID `{6AC1786C-016F-11D2-945F-00C04fB984F9}`) defined `LDAPServerIntegrity=4,1`; the Security Settings engine re-applies it at boot and
refresh and overwrote the registry value. `dc1-policy restore` sets the template to `4,2` and `check` fails while the GPO says anything else.
The bind probe must use valid credentials (`svc-activediq`): a dummy password answers 49 at 2/2 too. Run log:
`windows-lab-runs/T-1265-dc1-signing-20261102.md`. After restoring VM 119 from any snapshot taken before 2026-11-02, run `dc1-policy restore`.

## 20. Child domain (dc2) (T-1233, for T-0786 / T-1234)

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


## 19. Live user-search run and its DC evidence (T-0765)

`lab/windows/bin/with-dc1-lock lab/e2e/live-user-search.sh EVIDENCE_DIR` boots a lab-built server against dc1, mints a console session through the real
sign-in API, runs `web/e2e/live-user-search.spec.ts` and records dc1's side with `lab/windows/bin/dc1-evidence` (read-only WinRM):

- `dc1-evidence now` prints dc1's own UTC clock (dc1's clock differs from the host's; take windows from it);
- `dc1-evidence events SINCE` counts Directory Service events 2887, 3039, 3074 since that instant (any is a failure, exit 3; 2889/3040/3041/3075 are recorded only);
- `dc1-evidence svc` shows svc-activediq's groups and whether it is, through nesting, in Domain Admins, Enterprise Admins, Schema Admins or Administrators (found by SID; exit 3 if so).

Needs `WIN_LAB_ENV` and `WIN_LAB_CA` as absolute paths (the env and CA files are gitignored and live in the main checkout), docker, go, node with the
Playwright browser, and `pip install pywinrm requests-ntlm`. The script refuses to run outside `with-dc1-lock`. First record: `windows-lab-runs/T-0765-live-boot-20261101.md`.

## 20. Channel-binding acceptance: binds succeed at signing required + CBT Always, and dc1 logs no 2887/3039/3074/3075 (T-0148)

`lab/windows/bin/gssapi-lab accept` is the TM-TB3-T3 acceptance. Run it like every dc1 proof, under the lock, with
`WIN_LAB_ENV`, `WIN_LAB_CA` and `WIN_LAB_DC_ADDR` set (sections 10, 15, 18):

```
lab/windows/bin/with-dc1-lock -- bash -c 'lab/windows/bin/dc1-policy check && lab/windows/bin/gssapi-lab accept && lab/windows/bin/dc1-policy check'
```

| Step | What it does | Fails when |
| --- | --- | --- |
| policy | `require_policy` (section 18): both registry values 2 | either value is not 2; nothing else is touched |
| clock | dc1 minus host | over 60 s (Kerberos); never steps the clock (section 16) |
| A. correct binds | the four correct-binding tests of section 15 (keytab + gMSA, test handshake and `ad.Open`), window taken from **dc1's** clock | any of them is not `--- PASS` (a skip or a missing test is a fail), or the Directory Service log holds 2887, 3039, 3074 or 3075 in the window (+-1 s) |
| B. control | the wrong-binding test (refused with ldap 49); then polls (90 s max) until event 3039 is readable | the test fails, or 3039 never appears: an empty window would prove nothing |
| after | restores `16 LDAP Interface Events`, re-checks 2/2 | the policy moved during the run |

Exit 0 and the line `ACCEPTANCE PASSED` only if every step holds. It also prints the context ids it queried (2886, 2888, 2889, 3040, 3041) so a
reader can see what else the DC said. The judge, query builder and parser are pure functions in `lab/windows/lib/cbtevents.py`; the offline proof
is `lab/windows/tests/test_cbt_acceptance.py` (`make lab-test-windows-unit`, no Windows needed): each named event in the window fails the run,
events outside the window do not, a control without 3039 fails, a skipped bind is not a pass, drift of the policy fails.
2887 is a daily DC summary, so a 2-second window cannot prove it absent by itself; the run log also lists everything the queried ids logged in the
preceding 26 h. Run log and broken-run proof: `windows-lab-runs/T-0148-cbt-acceptance-20261102.md`. Needs the keytab and gMSA files from `gssapi-lab prepare`.
