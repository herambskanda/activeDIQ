---
name: member-kinds-lessons-2
description: T-1586 part 2 - classes table, member Actions, lab test traps (wantRule clash under -tags lab, NestingCycle)
metadata:
  type: reference
---

- Unit-test helpers share a package with `-tags lab` files: a helper name in a unit test (`wantRule`) collided with `wk_lab_test.go` and broke only the lab build. Run `go vet -tags lab ./pkg` after adding any test helper.
- Kind 11 refuses a nest that closes a loop (`NestingCycle`); build existing circles via the admin connection, not kind 11.
- Membership Actions: add vs nest are separate Actions (one permission per Descriptor); the step targets the group, the member is `Touched`.
- OU delete with children is a `PlanRefusal` code carrying the count (`ou_not_empty_<n>`); kind 13 and OU delete have empty Diff (T-1823 skips them).
- Membership Apply/Verify test: `operation.NewRunner` + `storeFace{action}` + `scopeAuthz{}` + `FreshStepUp: true` with the `dirFake` (members map).
