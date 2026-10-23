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
