---
title: "Module: notify"
date: 2026-10-30
updated: 2026-10-30
status: review
owner: heramb
author: backend-engineer
ticket: T-0950
tier: server
---

# Module `notify`

**Purpose.** The one door through which an administrator changes the tenant's mail settings: the allowed
recipient domains (what counts as an internal address) and the SMTP relay. Everything else about mail
(sending, the DM-84 Delivery record, the address parser) is the library `internal/platform/notify/…`, not
this module.
**Owner:** backend-engineer. **Epic:** E-002. **Spec:** [reports-2a](../../../product/specs/reports-2a.md) §8.4, [reports.md](reports.md) §7.2 and §8.
**Parity:** ADM-101 (scheduled report mail transport), ADM-205 (mail settings).
**Capabilities required (`Requires()`):** none; the settings are activeDIQ's own, whichever directory is connected.
**Platform matrix:** windows / linux-oci / saas: same.

## Owned tables

None (F1). The tables belong to the library packages that read and write them, and `modules/notify`
writes through `settings.Store` inside the runner's transaction.

| Table | Entity (DM-nn) | Migration | Owner package | Retention |
| --- | --- | --- | --- | --- |
| `notify_settings` | DM-82 (smtp channel + allowed domains) | 0059 | `platform/notify/settings` | life of the tenant |
| `notify_deliveries` | DM-84 | 0059 | `platform/notify/delivery` | no delete path; immutability trigger on identity columns |

## Contributions (what `Register` registers)

| Kind (Registrar method) | ID | Notes |
| --- | --- | --- |
| Action (EP-3) | `notify.settings.update` | permission `notify.settings.update`; **StepUp** and **ControlPlane** (TM-D30 SX-7; the permission is in `authz.neverCrossPrefixes`, so no group, token, automation policy or hybrid correlation carries it); reversible (inverse = before-image); optimistic `version`, a concurrent change gives `ErrStaleState`; input `#/components/schemas/NotifySettingsUpdate` |
| AuditKind (EP-7) | `notify.settings.updated` | changes: `allowed_domains`, `smtp_host`, `smtp_port`, `smtp_security`, `smtp_from`, `smtp_plaintext_opt_in`, before and after; no secret exists in the settings |

No API operation yet: the HTTP operation, its OpenAPI schema and the `policy.yaml` step-up row are a follow-up (they cannot land before the contract has the permission).

## Library behind it (`internal/platform/notify/…`)

| Package | Job |
| --- | --- |
| `mailaddr` | the one strict addr-spec parser; IDNA ToASCII canonical form; the string classified is the string on `RCPT TO` |
| `settings` | `Settings`, `Update.Normalize`, `Classify` (exact match, no subdomains, empty list ⇒ all external), `Store.Get/Set` |
| `mail` | `Sender.Send` over `egress`: STARTTLS required (no downgrade), implicit TLS, plaintext only with opt-in, one recipient per SMTP transaction, typed `*mail.Error` |
| `mailtest` | in-process SMTP catcher for tests (plain, STARTTLS, implicit TLS, stripped STARTTLS, rejections, down) |
| `delivery` | DM-84: `Deliveries.Enqueue/ForSource/Get`, `Dispatcher.DispatchDue` (lease claim, per-recipient outcome, backoff 1m/5m/30m/2h, `given_up` with a reason), audit `notify.delivery.queued|sent|given_up` |

## Dependencies

- **`platform.Deps` fields used:** none yet (`New` accepts and ignores them; the Action is stateless).
- **`directory.Services` fields used:** none.
- **Other modules' Actions called by ID:** none.
- **Datasets consumed:** none.
- **Writes to other owners:** none. `settings.Store.Set` takes the Action's `step.Step`.
- **Third-party libraries:** `golang.org/x/net/idna` (BSD-3-Clause) for the canonical domain form. No goroutines, timers or listeners.

## Web module

None yet.

## Security notes

- Widening the allowed domains turns external addresses internal and so lifts the external-recipient restrictions of report delivery; changing the relay re-points every outbound mail. Hence StepUp + ControlPlane (TM-D30 SX-7, [reports-schedules-security-review.md](../reports-schedules-security-review.md) §4).
- SMTP AUTH credentials are not held yet; when they are, they are sealed under the tenant DEK (backlog).
- Egress policy applies to the relay connection; a denial gives up the Delivery at once (`destination_denied`) and is audited.
- No message body, subject or address is written to the audit trail (DM-84.I1).

## Changelog

- 2026-10-30 · T-0950 · created: `notify.settings.update`.
