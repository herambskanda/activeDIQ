---
title: "ADM-134 impersonate-as-admin: the DC sees the service identity, the audit names the technician"
date: 2026-11-05
updated: 2026-11-05
status: review
owner: heramb
author: security-architect
ticket: T-1601
binding_sources: ADR-0005 rules 7, 11; domain-model.md DM-11 (I1, I5); ADR-0002 rule 9; specs/ad-forest-connection.md; m2b-plan.md decision 8
sources_last_checked: 2026-11-05
---

# ADM-134 "Impersonate as Admin": confirmation spec

## 1. Conclusion first

**The mechanism already exists by construction, and it is stronger than ManageEngine's.** Every
directory write runs on the connector's one bound session. The technician is never a principal on
the wire. The DC log names the bound service identity, and the activeDIQ audit chain names the
technician. We are not ManageEngine's "Impersonate as Admin": that mode is a technician-selectable
switch tied to CVE-2025-11670, NTLM hash exposure
([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11670); register row in
`knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md`). We have
no per-technician credential, so we have no mode to switch and nothing equivalent to leak.

**One small gap exists, in correlation rather than in privilege (§5).** The audit event for a
write names the technician and the connection, but it does not stamp the DC or the bound
credential. An auditor holding a DC log line cannot join it to the audit event without the
operation row. A build ticket is opened (§6). **ADM-134 needs no other build work beyond
documentation.** There is no privilege gap between the PRD's "no native AD rights" posture and
the connector credential model (§4).

## 2. How the identities separate (code citations)

| Claim | Where it is enforced |
| --- | --- |
| The initiator chain is carried in the step token and nothing else carries authority | `Step.Actor()` returns `authority.Chain` — `internal/platform/operation/step/step.go:105`. `authority.Chain{Requester, Via}` is `internal/platform/authority` `Chain` (requester = "the real human behind a delegated account", `Via` = API token or automation policy). ADR-0005 rule 7 forbids using an approver's authority. |
| The audit event names the chain | `audit.Event.Actor authority.Chain` — `internal/platform/audit/audit.go:78`. Step events are built with `Actor: c.op.Chain` — `internal/platform/operation/apply.go:52-54`. The chained envelope stores `Requester` and every `Via` principal — `internal/platform/audit/chainer.go:70` and `:80`. **These are the exact fields for AC 2: `Envelope.Requester` (technician) and `Envelope.Via`.** The identifiers are pseudonymous `PrincipalID`s, not names (`authority.PrincipalID`), so the chain stays exportable without personal data. |
| The connector identity is one credential per connection, set once | DM-11 I5: a credential's identity never changes in place; a row binds to one connection for its life (domain-model.md, DM-11). `ad.Credential{BindName, Password}` is the only holder of the secret and is used only inside `bind()` — `internal/connector/ad/session.go:~27-35`. |
| One bound session serves all handlers | `openBackend` calls `ad.Open(ctx, cfg)` once and builds every handler over that one session — `internal/compose/connector/backend.go:84`. A session has either `Credential` or `Kerberos`, never a per-request identity (`Config`, `session.go`). |
| The technician reaches the connector only as audit context, never as a bind | The write handler copies `acting.AccountId` and `acting.ApiTokenId` into its local `Event.Account` and `Event.Token` — `internal/connector/write/handler.go:176`. The event "carries identifiers only" (`internal/connector/write/record.go`). No code under `internal/connector` binds, delegates or impersonates on behalf of that account (checked: the only binds are `SimpleBind` at `session.go:201` and `GSSAPIBind` at `kerberos.go:176`, both from the connection's own credential; searched for S4U, proxied authorization and constrained delegation — none). |

## 3. Evidence for AC 1 (Samba lab, 2026-11-05)

Lab brought up from this worktree with `make lab-up`. The write was a replace of
`description` on `CN=Priya Ortiz,OU=Users,OU=Marketing,OU=Managed,...`, made over LDAPS as the
delegated service account `svc-activediq`. The technician identity `tech-alice` existed only in the
environment of the writing process. Samba's `dsdb_audit` was raised to 5 for the run
(`dsdb_audit:3`, the lab's committed setting in `lab/samba/entrypoint.sh`, logs failures only).

```
Auth: [LDAP,simple bind/TLS] user [LAB]\[svc-activediq@lab.activediq.test] ... status [NT_STATUS_OK]
  became [LAB]\[svc-activediq] [S-1-5-21-2197964389-1239679761-1112471443-1103]
DSDB Change [Modify] at [Thu, 05 Nov 2026 10:21:29 UTC] status [Success]
  SID [S-1-5-21-2197964389-1239679761-1112471443-1103]
  DN [CN=Priya Ortiz,OU=Users,OU=Marketing,OU=Managed,DC=lab,DC=activediq,DC=test]
  attributes [replace: description [T1601 marker write 4]]
```

`grep -c tech-alice /var/log/samba/log.samba` returned **0**. The DC log names the service
SID `-1103` for both the authentication and the change.

**Limits of this evidence, stated plainly:**

- It exercised the wire path (a delegated LDAPS bind plus a modify). It did not drive the product's
  full operation pipeline, because no write Action is wired end to end to the lab yet. The
  build ticket (§6) adds that end-to-end test.
- Samba's `DSDB Change` is not a Windows Security-log event. Whether a real DC's 4738 or 5136
  event shows only the service account is the same property for a gMSA bind, but is `[UNVERIFIED]`
  until it is run in the Windows lab (`lab/windows`). The Windows lab test belongs in the same build
  ticket.
- The marker value is an attribute value the DC does log. See invariant I-2.

## 4. Gap analysis: "no native AD rights" against the credential model

PRD posture: the connector holds delegated rights only, never Domain Admin (ADR-0002 rule 9;
DM-11 I4; `specs/ad-forest-connection.md` V7 refuses an identity in Domain Admins at activation).
"Impersonate as Admin" in ManageEngine exists because its service account is overprivileged
and its technicians have a mixed model of native rights and service-account rights.

| Question | Finding |
| --- | --- |
| Can a technician hold a native AD right through us? | No. Technician rights live in activeDIQ RBAC and delegation scope, enforced before the write against live facts (ADR-0005 rule 7). The directory grants the technician nothing. |
| Can a technician choose which identity a write runs under? | No. There is no field, flag or role for it. The identity is the connection's DM-11 row. |
| Can the service identity be used beyond the technician's authority? | Only if the Authorize recheck is bypassed. That is already a hard property of the step token (`ErrDenied`, `step.go`) and is covered by the pipeline's own tests, not by this spec. |
| Does the technician ever bind to the DC? | Only for `VerifyUser`-type self-service flows, where the end user (never a technician) authenticates as themselves. Those are the user's own events and are out of scope for ADM-134. |
| Is the DC-visible identity the least-privilege one? | Yes when the customer follows the delegation plan: gMSA on Windows, AES keytab for a dedicated account on Linux (ADR-0002). A customer who instead supplies a Domain Admin password is refused at activation (spec V7). |

**No privilege gap.** The residual risk is the service account itself: it is a Tier-0-adjacent
credential that sees every write, so a compromise of it is a compromise of everything it is
delegated. That risk is carried by the credential-custody design and the threat model (TM-A,
TB-3), not by ADM-134.

### Invariants this spec fixes (to be tested)

- **I-1 One identity on the wire.** For any operation, the set of principals the DC authenticates
  from activediq's connector is exactly one: the connection's bound credential. No technician,
  token or approver principal ever binds, delegates or is proxied.
- **I-2 No technician identifier in directory-visible values.** No Action writes a technician or
  token identifier (the `PrincipalID`, an account name or an email) into a directory attribute,
  including `description`, `info` or a reason field. The DC's own change log records written
  values, so doing so would leak the attribution into the DC log and contradict the claim above.
  The attribution lives in the activeDIQ chain only.
- **I-3 Authority is the initiator chain.** The audit `Requester` is the human behind the write;
  an approver appears only in the approval event, never as `Requester` of the step event.
  (Existing rule: ADR-0005 rule 7.)

## 5. The one gap: the audit event cannot be joined to the DC log

Per-technician attribution, the "leapfrog" in the parity matrix (enhancement 13), means an
auditor takes a line from the DC's log, finds who it was in activeDIQ, and the reverse. Today:

- The DC log gives: bound identity SID, time, DC, target DN and attribute names.
- The step audit event gives: `Requester`, `Via`, `Target.Connection`, target GUID, step key,
  plan hash (`apply.go:52-54`, `chainer.go:60-90`). It does **not** stamp the DC (the DC pin is
  held on the operation row, `Pins`) or the DM-11 credential ID. Only the tier0 events carry `dc`
  (`internal/platform/operation/tier0.go:63`).

The join is still possible: `Target.Connection` leads to the DM-11 row, and the operation row has the
pinned DC. But it depends on rows that are not in the tamper-evident, exportable chain (the metadata
row of a replaced credential stays only while a DM-24 or DM-25 row references it, DM-11 I5). For an auditor reading an
export, the chain alone must show "this event was transported by credential X on DC Y".

**Decision (security-architect, no CEO input needed; it is an implementation detail of our own audit
trail):** stamp two public details on every step event that writes to a directory: `dc` (the pinned
DC host) and `credential_id` (the DM-11 row ID). Do **not** stamp the bind account name or SID in the
event: both are in the DM-11 metadata, which is the sole source, so a rename in the directory cannot
fork the record. The chain stays free of personal values (ADR-0005 rule 11).

## 6. Build ticket

Opened as T-1629, a separate build ticket for `backend-engineer`, `security-sensitive`, parity ADM-134:

1. Add `dc` and `credential_id` details to the step audit event (`operation/apply.go`, the code
   that builds `c.event`); keys in increasing order as `audit.Event.Details` requires.
2. Fitness test I-2: a corpus check that no registered Action's plan diff writes a
   `PrincipalID` or account identifier into a directory attribute.
3. Lab e2e (Samba, then Windows lab): run a real operation as a technician, read the DC log, and assert
   the DC log names only the bound SID, the technician token never appears in it, and the audit
   event carries `Requester`, `dc` and `credential_id` that join to it.
4. Customer-facing documentation: "How to attribute a DC event to a technician" (for `docs-writer`).

## 7. Result against the ticket's acceptance criteria

1. **AC 1:** met on Samba, §3 (limits stated; Windows event IDs `[UNVERIFIED]`, assigned to the build
   ticket).
2. **AC 2:** met, §2. Technician = `Envelope.Requester` / `Envelope.Via` (`chainer.go:70,80`,
   `audit.go:78`); the connector identity is the transport, reached via `Target.Connection` → DM-11.
3. **AC 3:** one correlation gap (§5) found, so a build ticket is opened (§6). There is no privilege
   or mechanism gap, so no further build is needed beyond that ticket and the documentation.
