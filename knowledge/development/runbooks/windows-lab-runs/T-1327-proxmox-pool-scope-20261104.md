---
title: T-1327 — Proxmox lab token proven on the real host, dc1 snapshot clean-signing-2026-11-02
status: draft
owner: devops-engineer
updated: 2026-11-04
---

# T-1327 — pool scope proof and dc1 snapshot (D-0022, A-0038)

Run 2026-11-04 from the build host with the token the CEO bootstrapped at 07:43Z (`lab/.proxmox-lab.env`, mode 0600, read from the
main checkout via `PROXMOX_LAB_ENV`). No secret, token value or host address appears below. Node `prod1`. Every dc1 step under `with-dc1-lock`.

## 1. First real-host run found a defect (fixed in this ticket)

`proxmox-lab verify-scope` (as shipped by T-1326) **failed closed** on the real host:

```
verify-scope FAIL: token can see VM 119 which is not in adiq-lab
verify-scope FAIL: VM 119 (dc1) is not in pool adiq-lab
```

Cause: the driver read pool membership from the `pool` field of `GET /cluster/resources?type=vm`. The real host does not send that
field for this token (`pool: null`), and the offline stub had assumed it did. `GET /pools/adiq-lab` is 403 (`Pool.Audit`, deliberately not held),
but `GET /pools?poolid=adiq-lab` returns the pool's members the token holds `VM.Audit` on. The driver now reads membership there; the stub
models the real behaviour (no `pool` field in resources). `make proxmox-lab-test`: 43 tests OK.

## 2. Acceptance 1 — scope on the real host

`proxmox-lab verify-scope` → `verify-scope OK: the token sees only pool adiq-lab and holds only the lab role` (exit 0).

`proxmox-lab list` → `119  win-dc1-activediq  running` (the only VM visible; `/cluster/resources?type=vm` lists only 119).

Token permission listing (`GET /access/permissions`):

```
/pool/adiq-lab: 16 privileges
/sdn/zones/localnetwork/vmbr0: 16 privileges
/storage/local-lvm: 16 privileges
/vms/119: 0 privileges   (pool membership entry, no propagated privileges)
distinct: Datastore.AllocateSpace, Datastore.Audit, SDN.Use, VM.Allocate, VM.Audit, VM.Config.CDROM, VM.Config.CPU,
  VM.Config.Disk, VM.Config.HWType, VM.Config.Memory, VM.Config.Network, VM.Config.Options, VM.Console, VM.PowerMgmt,
  VM.Snapshot, VM.Snapshot.Rollback
Sys./Permissions./User./Pool./Realm./Group. privileges held: none
```

Out-of-pool VMs, addressed directly with the token (read and a start request; all refused by Proxmox, nothing started):

```
GET  /nodes/prod1/qemu/{100,101,102,110,200,999}/config        -> HTTP 403 Permission check failed (/vms/<id>, VM.Audit)
POST /nodes/prod1/qemu/{100,101,102,110,200,999}/status/start  -> HTTP 403 Permission check failed (/vms/<id>, VM.PowerMgmt)
```

The driver's own guard: `proxmox-lab start 100` → `refusing VMID 100: it is not a member of pool adiq-lab` (exit 2, no call addressed to VM 100).
Note: Proxmox answers 403 for both existing and non-existent VMIDs, so this probe cannot tell which of those IDs exist; it shows the token
holds no privilege on any VM except 119.

## 3. Acceptance 2 — dc1 snapshot

Under `with-dc1-lock`, `dc1-policy check` (registry, Default Domain Controllers Policy template, cleartext simple bind as `svc-activediq`):

```
LDAPServerIntegrity = 2
LdapEnforceChannelBindingTokens = 2
Default Domain Controllers Policy GptTmpl.inf LDAPServerIntegrity = 2
cleartext simple bind to 192.168.1.250:389 as svc-activediq@win.activediq.test -> resultCode 8 (strongerAuthRequired)
dc1-policy: enforced
```

(The registry value is `LdapEnforceChannelBindingTokens`; the ticket text calls it `LdapEnforceChannelBinding`.) In the same lock hold, the check
re-ran and `proxmox-lab snapshot 119 clean-signing-2026-11-02` was taken (disk only, VM running, no vmstate), then `proxmox-lab snapshots 119`:

```
before-lab
before-dc            DC1 renamed, static IP 192.168.1.9, scripts copied, before domain promotion
before-static-ip     before static IP on 192.168.1.9
clean                Provisioned lab: DC1, win.activediq.test, CA, LDAPS, svc-activediq, audit GPO. Built 2026-10-28.
before-fs1           before adding fs1 (A-0028); dc1 at 192.168.1.250
clean-signing-2026-11-02   dc1 clean: LDAPServerIntegrity=2, LdapEnforceChannelBindingTokens=2 (T-1265), taken T-1327 signing 2/2
current              You are here!
```

The name carries 2026-11-02 (the T-1265 signing-2/2 date the CEO asked for); it was actually taken 2026-11-04. No snapshot was deleted.
dc1 was left running and unchanged.
