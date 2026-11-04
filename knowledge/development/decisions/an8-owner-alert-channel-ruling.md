---
title: AN-8 break-glass owner alert — channel ruling (TM-D16 part 2, §7.6 rule 4) and T-0801 split
date: 2026-11-04
updated: 2026-11-04
status: review
owner: security-architect
kind: security-ruling
ticket: T-1475
binding_sources: threat-model.md §7.6 rules 2, 3, 4; console-sso.md FSSO-3, FSSO-5; migrations/0048_authn_authority_factor.sql; internal/platform/notify/delivery
---

# AN-8 owner alert: which channel, and what happens when it is down

## Ruling (RULING AN8-A1)

**The alert is written to the `authn_authority_notices` outbox, in the same transaction as the
break-glass session. `platform/notify` is only the transport that a drain job feeds from the outbox.**
The sign-in path never calls `notify` and never waits on a relay.

| Step | Where | Rule |
| --- | --- | --- |
| 1. Record | `internal/platform/authn`, inside the AN-8 success (and the 10-failures-in-an-hour trip) transaction | One outbox row per event, written with the session row. Both commit or neither does. Events: `break_glass_used`, `break_glass_failures` (the CHECK on `event` is extended by migration) |
| 2. Fan out | Drain job, tenant context, not the sign-in path | Recipients are resolved from `tenant-owner` **at drain time**, one `notify` Delivery per recipient (DM-84). The sign-in path therefore never fails on an owner lookup |
| 3. Send | `platform/notify/delivery` | Existing lifecycle: queued, failed with backoff, `given_up` after `MaxAttempts`; its audit events carry ids and codes, never an address |
| 4. Mark | Drain job | `delivered_at` moves only when the Delivery row exists (enqueued), not when the mail is accepted; the Delivery owns the send state |

### Why the outbox, not notify directly

1. **Break-glass is the path used when everything else is broken.** Mail relay, DNS or egress may be
   the very thing that is down. Calling `notify` inline would couple recovery to the relay, or force a
   try/catch that swallows the alert. A transactional row has no such coupling.
2. **No lost alert, no phantom alert.** The row commits with the session. A crash after commit is
   drained on restart; a rolled-back sign-in leaves no alert about a session that does not exist.
3. **Reuse, not a second mechanism.** The table is already the TM-D19 rule 2 recipient-per-row,
   tenant-RLS, `delivered_at`-only-moves outbox, and `notify/delivery` already has retry, backoff, lease and
   `given_up` audit. The new code is a drain job and two enum values.
4. **The trigger is hard to forge.** The row is written by the authn package alone (the table comment
   says only `internal/platform/authn` references it in SQL). Nothing else can raise or suppress it.

Rejected: *notify directly from the handler* (couples recovery to the relay, loses the alert on a crash
between session commit and enqueue). *Outbox only, with its own mail sender* (a second retry, backoff and
audit implementation; the TM-D19 notices need the same drain, so both go through one drain job).

## When the channel is down (acceptance 1)

| Failure | Break-glass sign-in | Alert | Audit |
| --- | --- | --- | --- |
| Mail relay or egress down | Succeeds, unchanged | Delivery goes `failed`, retried with backoff to `MaxAttempts`, then `given_up` | `notify` audits each attempt and the give-up; the drain also audits `an8_alert_given_up` with the outbox id |
| Drain job not running | Succeeds | Row stays `delivered_at IS NULL`; the oldest pending age is a health metric and the Overview shows "break-glass alert pending" to `tenant-owner` on next sign-in | `an8_alert_pending_over_threshold` at 15 min (once per row) |
| Outbox insert fails (DB error) | The session row shares the transaction, so a DB failure fails the sign-in with the uniform `401` like any other store fault; there is no state with a session and no alert | n/a | The failure is audited by the existing AN-8 store-fault path |
| No `tenant-owner` resolves at drain time | Succeeds | The drain writes a Delivery to the tenant's configured security contact if set, else marks the row `given_up` | `an8_alert_no_recipient` |

Hard rules: (a) the alert never gates, delays or alters the sign-in response or its timing (rule 2
latency floor holds; no alert-dependent branch before the response); (b) the session's audit event is
written first and does not depend on the alert; (c) an alert that is `given_up` is never silent: it
shows as a banner to every `tenant-owner` after their next sign-in (FSSO-6 pattern, no dead button);
(d) the alert body carries no password, token, session id or submitted username, only the account display
name, time, source address and "break-glass".

Residual **R-AN8-3**: an attacker who has used break-glass and can also keep the relay down delays the
mail; the banner and audit record remain. Accepted: a mailed alert is not a preventive control, the
CIDR allow-list (build 2) and the switch-off (build 4) are.

## Split of T-0801 (acceptance 2, 3)

All four touch `internal/platform/authn`, so they are a chain, one dependency each, not parallel work:

| Order | Ticket | Scope |
| --- | --- | --- |
| 1 | Owner alert + `realAN8Target` gate | Rule 3 alert, this ruling. First: carries the T-0497/T-0200 gate |
| 2 | Source-CIDR allow-list (depends on 1) | Rule 4, `an8_reach_rules` part 1 |
| 3 | AN-5/AN-7 hostname refusal (depends on 2) | Rule 4, `an8_reach_rules` part 2 |
| 4 | AN-8 switch-off / step-up on-again (depends on 3) | Rule 4 last sentence |

Tickets: T-1544 (1), T-1545 (2, depends T-1544), T-1546 (3, depends T-1545), T-1547 (4, depends T-1546). The director cancels T-0801 once they exist.

## Citations

Cited from `threat-model.md` §7.6 rule 4 (alert channel and failure mode) and `console-sso.md` FSSO-3.
The changelog of the threat model records the change.
