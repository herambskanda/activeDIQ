---
name: rights-check-lessons
description: Samba lab and rights-check (VerifyConnection AD half) gotchas from T-0096
metadata:
  type: reference
---
- samba-tool `dsacl set/delete`, `delegation add-principal/add-service/for-any-service`, `ou create` work in the lab container via docker exec.
- allowedAttributesEffective / allowedChildClassesEffective / sDRightsEffective / tokenGroups are constructed: need `Read`, not `Search`.
- Exclude Everyone / Authenticated Users / logon SIDs from "own" SIDs when blaming excess ACEs, else every identity is refused; use full token for missing-right checks.
- entra.go defines `guid()` in package rights: import the AD guid package as `adguid`.
- Test fake GUID generator must be 2 bytes (1-byte counter wraps at >255 objects).
- Samba can't prove SDProp inheritance, WAAG readability, Windows event-log sinks (follow-up T-0231).
- Samba omits sDRightsEffective on computer objects (CN=DC1) for non-admin callers; don't fail closed on absence alone, fall back to the parsed SD. Samba default broad ACEs on tier0: Send-To, Apply-Group-Policy, Unexpire-Password, Update-PNRB, Enable-Per-User-RevEnc (allowlisted in ad_policy.go). Docker may exist: `make lab-up` then `go test -tags lab`.
- C19 rights check (T-0362): tier0 ADSet.C19Rights() carries per-object rule-2 rights/owners; rights.c19() must match c.tokens (full token), NOT c.own — default FSP placeholders mean the classifier does not fail closed for AU/Everyone. Shared lab container may belong to another worktree (no lab/.lab.env): report lab tests unrun.
