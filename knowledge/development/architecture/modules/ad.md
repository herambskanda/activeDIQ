---
title: "Module: ad — account-state Actions (reset password, unlock, enable, disable)"
date: 2026-11-07
updated: 2026-11-07
status: draft
owner: heramb
author: backend-engineer
ticket: T-1584
tier: server
binding_sources: connector-contract.md §8.10; ADR-0003; ADR-0005 rules 1, 2, 6, 7, 9; TM-D16, TM-D28
---

# Module `ad`

**Purpose.** The help-desk-critical account Actions on an AD connection, parameterised by one `spec` row
each (`actions.go`): they differ in digest key, permission, class and after-state, not in shape.
**Owner:** backend-engineer. **Epic:** E-003. **Ticket:** T-1584. **Parity:** ADM-034, ADM-136.
**Capabilities required (`Requires()`):** `directory.ad`. **Platform matrix:** same on every platform;
Entra is not an `AccountProvider` (connector contract §8.10.10).

## Owned tables

None. The module writes nothing itself: Apply gives the connector kind and the runner's Step to
`directory/client.Client.Write`.

## Registered Actions

| Action | Permission | Class | StepUp | Secret | Kind (digest key) |
| --- | --- | --- | --- | --- | --- |
| `ad.user.resetPassword` | `objects.user.reset_password` | Irreversible | yes | yes | `ad.user.resetPassword` |
| `ad.user.unlock` | `objects.user.unlock` | Irreversible | no | no | `ad.user.unlock` |
| `ad.user.enable` | `objects.user.enable` | Reversible (inverse: disable) | no | no | `ad.account.enable` |
| `ad.user.disable` | `objects.user.disable` | Reversible (inverse: enable) | no | no | `ad.account.disable` |

Input: the account's `connectionId`, `objectGuid` and `namingContext` (canonical lower-case UUID text,
digest-bound); reset adds `mustChangeAtNextLogon`. The password is a transient secret input of the
submission (rule 9), never an input member: an unknown member is refused at Plan.

## Behaviour

- **Plan** reads the live account on the operation's pins through `client.AccountReader` and refuses
  a missing target, a non-user and a Tier-0 target (`tier0_target`, denied). The diff of reset is the
  must-change flag plus the *presence* of a secret. The other three kinds' digest binds no attribute
  (`accountkind.AttrsOf`), so their before and after are in `Preconditions`, not `Diff`.
- **Apply** calls `client.Write`, whose Step re-check is the TOCTOU guard (a target that left the
  technician's scope fails denied with a denial event). Errors map to the pipeline's typed errors with
  fixed texts; a credential step whose connector call fails mid-flight is `ErrOutcomeUnknown`.
- **Verify** re-reads the account, re-runs the Tier-0 check (`tier0_after_write` outranks every other
  reason) and compares with the kind's after-state.
- **Observe** reads the account on the pins for reconciliation; a must-change reset cannot be told from
  its before-state and reports `other`.
- **Inverse.** Unlock is Irreversible per connector contract §8.10.1 row 8 (the DC owns `lockoutTime`;
  no kind can set it non-zero), which differs from the ticket text that listed it as Reversible. Enable
  and disable return an input of their shared `AccountInput` shape; `ad.InverseAction` names the paired
  Action the undo layer applies it to. A step that changed nothing returns `ErrNothingToUndo`.

## Dependencies

`directory.Services.AccountReader` and `.AccountWriter` (`directory/client`). Nil until the composition
root wires a connector transport and a live account reader; the Actions then refuse every Plan and
Apply (`directory_unavailable`) rather than run without the directory.

## User lifecycle Actions (T-1585)

`lifecycle.go`: six Actions from one generic builder (`buildLife`) and a spec row each, over
`LifecyclePorts{Reader client.ObjectReader, Writer, Definitions}`. Parity: ADM-008 create, ADM-033 modify,
ADM-038 restore.

| Action | Permission | Descriptor class | Step class | Digest kind |
| --- | --- | --- | --- | --- |
| `ad.user.create` (secret input: the initial password) | `objects.user.create` | Lossy | Reversible (delete undoes it until the account joins a group) | `ad.object.create` |
| `ad.user.update` | `objects.user.update` | Reversible | Reversible | `ad.object.update` |
| `ad.user.delete` | `objects.user.delete` | Irreversible | Lossy with the Recycle Bin, else Irreversible | `ad.object.delete` |
| `ad.user.move` | `objects.user.move` | Reversible | Reversible (inverse: move back) | `ad.object.move` |
| `ad.user.rename` | `objects.user.move` (a modifyDN, TM-D19) | Reversible | Reversible (inverse: rename back) | `ad.object.rename` |
| `ad.user.restore` | `objects.user.restore` | Lossy | Lossy iff a retained link value stays dormant, else Reversible | `ad.object.restore` |

- **Create** validates the pinned Template (published, user, create, AD/hybrid, container allowed), applies
  `CheckInput`/`Effective`, renders the pinned NamingFormats (sAMAccountName, cn, displayName, UPN prefix +
  `upnSuffix`), reads the parent (a container, not Tier-0) and builds the digest attributes with
  `writechange.CreateAttrs`. Diff names are the digest names (`set:givenName`, `~rdn`, ...).
- **Update/create attributes** are an allow-list (`profileAttrs`); sign-in attributes (UAC, UPN/sAM on update,
  passwords, group links, SDs) are refused.
- **Move/restore** declare the destination parent through the kernel's new `Typed.AlsoAuthorize`
  (`operation.AlsoAuthorizer`): the runner authorises it live at Plan and again immediately before Apply, with
  the step's permission (ADR-0005 rule 7: source parent via the target's own ancestry, destination via this).
  Source and destination parents are also `Touched` for the Tier-0 re-read.
- **Restore class.** The ticket said Lossy because link values are not restorable; ad-expert (T-1585) and
  connector contract §8.10.3 kind 6 say a Recycle-Bin restore re-grants retained links, except links whose other
  end is itself still deleted. Plan lists each ("re-granted" / "will not return") from the show-deactivated-link
  read, and is Lossy exactly when one is dormant. Without the Recycle Bin restore is refused.
- **Inverse.** Move and rename return their own shape. Create/delete/restore pair with other Actions
  (delete/restore/delete) and return `ErrIrreversible` from `Inverse` until the undo layer exists.
- `directory.Services.ObjectReader` has no connector-backed implementation yet (see the follow-up ticket):
  nil makes every lifecycle Plan refuse `directory_unavailable`.
