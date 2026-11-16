---
title: Group-member and computer-reset fitness (GM1-GM4)
status: draft
owner: devops-engineer
updated: 2026-11-13
---

# fitness-group-member (GM1-GM4, T-1916)

Spec: `knowledge/development/architecture/connector-contract.md` §8.10.8 (kinds 11-13, T-1899), B1 key with
target class in `threat-model.md` §6.9a. Run: `make fitness-group-member` (part of `make fitness`).
Source: `tools/fitness/groupmember`; stdlib plus the generated connector proto only (no new dependency,
nothing for the licence register).

| Rule | What the tool reads | Fails when |
| --- | --- | --- |
| GM1 | non-test Go files containing `ad.group.addMember` / `removeMember` | a `Descriptor.Permission` outside the three group permissions, or none; a `Target:` that names the member; the step `Target` expression differs from the `WriteOp` `Target` |
| GM2 | `TestKindTableClosed`, `kindTable` | the closed list is not exactly the §8.10.1 digest keys; a `WriteKind` 11-13 constant is used outside the table (wired) but `kindTable` has no row, or the row has no class |
| GM3 | `guarded-v1` block, `internal/directory/guarded`, callers of `ComputerReset` | `reset_password` lacks `unicodePwd[user]`; `reset_computer` is not exactly `unicodePwd[computer]`; bare `unicodePwd` under another class; the Go table lacks either key; a file calling `ComputerReset()` declares anything but `objects.computer.reset_account` (B4) |
| GM4 | §8.10.1 rows, generated enum and `WriteChange` oneof, `TestWriteKindList` | a row's number differs from the enum value or the arm number; an enum value has no row; the pinned test list differs from §8.10.1 |

**Pending is not a pass.** With no group-member Action and no `guarded` package in the tree, GM1 and the
Go-table half of GM3 print `pending`. They turn active by themselves when the code lands (backend-engineer
Actions, directory-engineer `guarded`). GM1's Target/permission rules are file-level and syntactic: an Action
built so that the group Target is not a literal `Target:` field is reported as "cannot find both Targets",
which fails rather than passes.

**Proof it catches violations.** `go test ./tools/fitness/groupmember` has a failing tree per rule;
`make ci-proof` runs the real CLI on throw-away trees (clean pass, then each violation rejected).
Adding a fourteenth kind means changing §8.10.1, `TestWriteKindList` and `TestKindTableClosed` together.
