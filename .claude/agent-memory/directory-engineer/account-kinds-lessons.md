---
name: account-kinds-lessons
description: T-1583 account write kinds — leaf digest pkg, accountkind single definition, test traps
metadata:
  type: project
---

- `step` imports `store`; the connector binary must not (fitness `forbidden`), so the digest lives in leaf `operation/digest` and `step` aliases it.
- `accountkind` is the one definition of the 4 kinds: server `ChangeFromAttrs`, connector `AttrsOf`. Connector cannot know the server's `TargetRef.Class`, so its digest accepts any class the kind allows and checks live class separately.
- Client `deriveChange` runs AFTER the `ErrDigest` check (replayed digest must give ErrDigest) and demands canonical lower-case UUIDs.
- Test-only kindTable row `user.set` must not reuse a real WriteKind (it was 7 = reset); client tests mint steps for other kinds via `stepKind`/`stepDiff` vars.
- Fake property guard refuses everything (fail-closed): set `r.prov.guard = &stubGuard{}` in write tests.
- `ldap.ModifyRequest` ops: 0 add, 1 delete, 2 replace.
- `tools/fitness/api` TestFixtureEnvIsClean fails without `web/node_modules` (ajv) — environmental, not ours.
- Unproven on Samba/Windows (ticket T-1638): policy-hints control, lockoutTime replace-0, UAC delete-old/add-new.
