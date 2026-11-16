---
title: "ADR-0017: Group-member write steps carry Target.Class=group as an asserted, unhashed class; the connector digest stays class-free"
date: 2026-11-16
updated: 2026-11-16
status: ratified
ratified_on: 2026-11-16
ratified_by: factory-director
decision: D-0038
author: solution-architect
kind: technical
ticket: T-2214
amends: connector-contract.md §8.10.3 kinds 11 and 12 (v1.6, T-1899)
fitness: GM1 (extended), GM5 (new) — neither in CI yet, so not `accepted`
---

# ADR-0017: Group-member write steps carry `Target.Class=group` as an asserted, unhashed class

**Status:** ratified 2026-11-16 (D-0038). Security claim verified against `kinds_group.go:171` at review; security-architect reviews it again on T-2217. `accepted` when GM1 (extended) and GM5 run green in `make ci`.

## Context

T-1915 (Actions for kinds 11/12/13) cannot build as specified. Three accepted rules collide:

1. `Descriptor.TargetClass="group"` makes the kernel (`runner.checkPlan`, `internal/platform/operation/runner.go:537`) require `StepPlan.Target.Class == "group"`. This is how rbac.GroupReach / TM-D18 is bound: the authz Target is the group, and the kernel refuses a step aimed elsewhere.
2. `client.WriteOp.derive` (`internal/directory/client/write.go:382`) refuses any non-empty `Target.Class` for every kind except OBJECT_CREATE ("class is read live"), and `write_test.go:692` asserts it. Contract §8.10.3 says the group target "carries no class" and the digest is class-free.
3. GM1 requires the step's authz `Target` expression and the `WriteOp` `Target` expression to be textually identical (the member must not be passable as the target).

A class-bearing step fails the client; a class-free step fails the kernel. T-1586 (done, branch `factory/T-1586`, **not merged to main**) built the same Actions with the group ref carrying class `group` and passes only because its tests use a fake writer. It has the same latent defect.

## Decision

**Neither (a) nor (b) as literally framed; the closest is (a), without a new field.**

- `StepPlan.Target.Class = "group"` stays. It is the kernel's authz class and is already bound by the plan hash (the whole `StepPlan` is hashed in `checkPlan`). No new `StepPlan` field and no kernel change: every other Action keeps its meaning of `TargetClass`.
- `WriteOp.derive` is amended: for `GROUP_MEMBER_ADD` and `GROUP_MEMBER_REMOVE` only, `Target.Class` must be **empty or exactly `"group"`**; any other value is `ErrInvalidOp`. The value is an **assertion, not a digest input**: it is not hashed, not put on the wire, and the connector's digest and wire shape are unchanged (contract §8.10.3 stays: digest class-free).
- The connector already reads the group's live `objectClass` and refuses a non-group (`kinds_group.go:171`); that live check, not the asserted label, is the enforcement. A caller who asserts `group` for a non-group gets `TARGET_CHANGED`/refusal at Plan and Apply.
- All other kinds keep "class is read live; empty class" except OBJECT_CREATE and the account kinds' existing `AllowsClass` rules.

## Options considered

| Option | Verdict |
| --- | --- |
| (a) literal: new unhashed `StepPlan` authz-class field the kernel compares | Rejected. Touches the kernel and ADR-0005 shape for one kind family, adds a second place a class lives per step, and `Target.Class` already does the job and is already hashed in the plan. |
| (b) digest includes class `group` for kinds 11/12 | Rejected. Changes the wire digest, the connector codec (`writechange`), test vectors CC-WK-45..62 and the already-merged T-1913 for a constant that carries no information (a member-class-free target is always a group; the connector verifies it live). |
| (c) Descriptor.TargetClass left empty for these Actions | Rejected. The kernel would stop refusing a step aimed at the member; GM1 would be the only guard, and it is static. The runtime check is the defence in depth for TM-D18. |
| (d) chosen: accept the one literal `"group"` on kinds 11/12, unhashed | Smallest change, GM1 text-identity holds, digest and kernel untouched. |

## Consequences

- Change is one function and one test in `internal/directory/client` (T-2215), not a contract wire change. T-1913 stays valid.
- `write_test.go:692` is inverted: `"group"` accepted, any other class (`"user"`, `"computer"`, `"contact"`) refused, and the derived `wire` is byte-identical with and without the class.
- GM1 stays as written. Its fixture set gains: the member-targeted Action fails (unchanged), and a step whose `Target.Class` is not `group` fails.
- The asserted class is never an authorisation input on its own: the kernel check compares it to the Descriptor, rbac.GroupReach resolves the group live, and the connector reads class live.

## Security

The new accepted input is a label that equals what the connector independently reads. A forged `group` on a non-group target is refused by the connector's live class read (CC-WK check GM5). A wrong class such as `user` cannot pass either the kernel (descriptor `group`) or `derive`. The TM-D18 invariant ("authz Target is the group") is unchanged.

## Fitness function

- **GM1 (extended):** static check as in contract v1.6, plus the registered Action's `Descriptor.TargetClass` must be `"group"` and Plan's step `Target.Class` must be `"group"` for `ad.group.addMember`/`removeMember`.
- **GM5 (new):** client test, runs in `make ci`: (i) `derive` for kinds 11/12 accepts `""` and `"group"`, refuses every other class; (ii) the derived `wire` and the connector digest input are byte-identical for `""` and `"group"` (class is never hashed); (iii) a connector test where the target GUID is a user with asserted class `group` is refused.
- Owner: devops-engineer (GM1/GM5 wiring), test-engineer for the vectors.
