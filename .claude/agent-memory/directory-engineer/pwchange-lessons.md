---
name: pwchange-lessons
description: T-1019 Cannot Change Password read — where it lives, why per-object, lab recipe that worked
metadata:
  type: reference
---

- Classifier is `sd.ClassifyPasswordChange` (internal/directory/sd/passwordchange.go); connector wrapper `ad.Session.ReadPasswordChange`. Zero value = NotConfirmed; state never non-zero beside an error.
- `nTSecurityDescriptor` is in `constructedReadOnly`, so paged `Search` refuses it: SD reads are per-object `Read`/`ReadDACL` only. A bulk SD read needs a design decision, not a quick hack.
- `sidEveryone` already exists in plan.go (package sd); `sidSelf` in grants.go. Reuse, don't redeclare.
- Lab test writes deny ACEs through PlanDACL (needs a one-GUID RightsCatalog mapping ab721a53 -> ControlAccess) + `labReplaceSD`; works on Samba first try. Users created with UAC 514 need no password.
- `make lab-up` took 540s this time; `make lab-down` after. Pre-existing red: fitness-safeprim (compose/server lab test unused import), fitness-corpus (mail undeclared).
- Order trap (T-1019 review): classifier must return NotConfirmed on acl.order_outcome (allow before deny); canonical-order tests use pcSD builder. Shared GOCACHE can be corrupted -> use a private GOCACHE.
- S1 (DirSync + nTSecurityDescriptor) is [UNVERIFIED]; inherited propagation is not replicated -> label by full-sync age. Follow-up T-1139.
