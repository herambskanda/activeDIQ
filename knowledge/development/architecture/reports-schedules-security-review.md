---
title: "Security review: step-up and conditional permission checks for report schedules (TM-D30)"
date: 2026-10-30
updated: 2026-10-30
status: review
owner: heramb
author: security-architect
ticket: T-0893
binding_sources: threat-model.md §5.15, §7.4 (TM-D16); ADR-0005 rule 8 and rule 10; modules/reports.md §6.6, §7, §8; specs/reports-2a.md §8.4, §8.5
reviewed_artefact: api/openapi/modules/reports.yaml on factory/T-0866 at f23f297cd (not yet on main)
sources_last_checked: 2026-10-30
---

# Security review: report schedules, external delivery and step-up

**Scope.** This review covers the step-up question that threat model §7.4 left open for reports. It
also reviews the conditional checks inside operations in the T-0866 contract
(`api/openapi/modules/reports.yaml`, branch `factory/T-0866`, commit `f23f297cd`). Those checks are:

- `reports.schedule.manage_all` for `owner=any` and for another owner's schedule;
- `reports.deliver.external` for external recipients;
- runner-bound run reads (modules/reports.md §6.6);
- downloads authorised by the Delivery row (modules/reports.md §7.2).

**Outcome in one paragraph.**

- **Step-up is required, but only conditionally and inside the operation.** A schedule write that
  leaves the schedule with at least one external recipient needs a fresh MFA (DECISION TM-D30
  below). `policy.yaml` gets **no `stepUp` row for any `reports.*` permission**. Its rows are keyed
  by an operation's `x-permission` and enforced by the API host before the handler runs
  (`internal/platform/apihost/chain.go:104`). A row on `reports.schedule` would put step-up on
  list, get and pause too. `reports.deliver.external` is bound to no operation, so fitness A13
  refuses it as a row (`tools/fitness/api/a13.go:18`).
- **Changing the allowed recipient domains needs static step-up.** Adding a domain turns external
  addresses internal, which bypasses both `reports.deliver.external` and TM-D30. The row enters
  `policy.yaml` when the `notify` settings operation lands (T-0950).
- **The contract has four authorisation defects (R1–R4) and two gaps (R5–R6)**, listed below and
  filed as T-0979 (contract), with T-0980 (kernel) and T-0981 (spec alignment) for the decision. The runner-bound reads and the Delivery-row downloads are sound as
  specified.

## 1. Why schedules with external recipients need step-up

§7.4 (TM-D16) puts an operation on the step-up list when a session hijack would turn it into one of
these:

- credential disclosure;
- escalation;
- a **standing** credential or channel;
- re-pointing an authority or an evidence stream.

Two rows already set the precedent for data streams: "Audit export, retention or SIEM-sink changes",
and the SIEM-destination row in `policy.yaml` ("can redirect or blind the tenant's audit stream").

**Threat (new row TM-TB15-T9).** An attacker with a stolen console session (X4 with a hijacked
cookie, or an unattended console) could export a report once. Step-up does not stop that: the
attacker downloads the file inside the session, and TM-TB15-T6 audits it. A schedule is different.
It is a **standing outbound channel that outlives the session**. Revoking the session, which is how
an incident ends (§7.3 Revocation), does not stop it. Every week it mails the owner-scope directory
to an address outside the organisation, under the owner's authority as it is at each fire.

The 2a library contains exactly what an attacker wants for reconnaissance:

- privileged group membership (GRP-02);
- stale and never-expiring passwords;
- disabled and inactive accounts;
- probable service accounts (E2, spec §6.7).

This is persistence plus exfiltration. It matches the §7.4 "re-points a stream" class.

**Why not step-up on every schedule write.** An internal-only schedule sends data to accounts and
allowed domains that the tenant has already declared its own. The TM-TB15-T2 residual covers it, and
step-up would add friction to the common case without closing a channel. Pause and delete only
reduce exposure. The friction of TM-D30 therefore falls on the rare case: a recipient outside the
organisation.

**What the competitor does.** We do not know whether ManageEngine ADManager Plus or ADAudit Plus
require re-authentication for scheduled-report recipients `[UNVERIFIED]`. ME-SEC does not cover
it. ME-SEC §4.1 does record that ADAP's reports, dashboards, alerts and exports took 28 SQL-injection
fixes in 2024
([ME-SEC §4.1](../../business/market-research/manageengine-ad-customer-voice-and-security.md),
[NVD CVE-2023-48792](https://nvd.nist.gov/vuln/detail/CVE-2023-48792)). The report and export surface
is where reviewers will look first.

## 2. DECISION TM-D30: conditional step-up for schedules that deliver outside the organisation

| # | Rule |
| --- | --- |
| SX-1 | Step-up applies to every `reports.schedule.*` Action whose **after-state** has at least one external recipient. That covers `create`, `update`, `resume`, and the undo of any of them. An external recipient is an e-mail address outside the allowed recipient domains, classified at Plan time against the list as it is then. An account recipient's own mail address counts as external under SX-5. The Action needs a fresh MFA within the tenant's step-up window (`internal/platform/authn/stepup.go`: 1 to 15 minutes). The predicate reads the after-state, so it needs no diff logic: an edit to the recurrence alone of a schedule with an external recipient also steps up. Removing the last external recipient does not. |
| SX-2 | `pause`, `delete` and `reassign` never step up. Pause and delete only stop delivery. Reassign leaves the schedule paused, and the new owner's `resume` steps up under SX-1. `runReportScheduleNow` is bookkeeping, not an Action. It sends only to recipients already confirmed under SX-1, so it does not step up. |
| SX-3 | **Enforcement point.** The operation kernel enforces SX-1, not the API host and not `policy.yaml`, so the rule holds for every origin: console, API, undo and any later automation. The kernel's `Descriptor.StepUp` is static today (`internal/platform/operation/operation.go:75`). T-0980 adds an input-derived predicate. The kernel evaluates it over the canonical, validated `Input` at submit (`submit.go:127`) and in the hold rule (`holds.go:70`). The Input is bound into the plan hash, so the check and the apply cannot see different recipient sets. `Test_stepup_flag_catalogue_matches_table` lists the conditional Actions as well. |
| SX-4 | **Non-interactive callers.** An API token or an automation cannot complete MFA. When one of them triggers SX-1, the operation is **held for an approval that carries step-up** (ADR-0005 rule 8, `holds.go` `HoldStepUp`). It is not refused, and it never passes silently. The HTTP shape of a held schedule write is T-0892's to define. An interactive human without a fresh MFA gets `step-up-required` (401) and changes nothing. |
| SX-5 | **Classify the address the mail is actually sent to.** An account recipient with attachment delivery receives mail at the account's address. At write time and again at every fire, that address is classified with the same rule as an e-mail recipient. If it is external, the delivery fails alone with the reason "account address is outside the allowed domains; use a link". A link carries no data: it needs a signed-in account holding `reports.export` (§7.2). Without this rule, choosing a recipient account would bypass `reports.deliver.external`. |
| SX-6 | **Confirmed means confirmed.** At fire time, an address that is external now and is **not** in the schedule's stored confirmed-external set fails alone with the reason "address became external; confirm it on the schedule". This happens, for example, after an admin removes its domain from the allowed list. The fire does not deliver it merely because the owner holds `reports.deliver.external` now. The owner re-confirms it through `update`, which steps up under SX-1. This narrows spec §8.4 fire-time check 3; T-0981 aligns the spec. |
| SX-7 | **Widening the allowed recipient domains needs step-up.** Adding a domain silently turns external addresses internal, which bypasses SX-1 and `reports.deliver.external`. The `notify.settings.update` Action (T-0950) carries static `StepUp`, because the same setting also holds the SMTP relay, and changing the relay re-points every outbound mail. Its permission gets a `policy.yaml` `stepUp` row with `ref: TM-D30` in the change that adds the operation. Matching rules for T-0950: <ul><li>the domain matches exactly, after IDNA ToASCII and lowercasing;</li><li>a subdomain matches only through its own entry;</li><li>the address is parsed strictly as one addr-spec, refusing a display name, a quoted local part, a comment, a source route, an IP-literal domain, more than one `@`, and CR or LF;</li><li>classification and the SMTP `RCPT TO` use the same canonical string, so no parser differential is possible.</li></ul> |
| SX-8 | **Audit.** The Action event records the confirmed external addresses (spec §8.6, already required), plus `step_up: fresh` and the factor kind. A held SX-4 operation records the approver. A delivery that fails under SX-5 or SX-6 records its reason code. |

**Residual (TM-R26).** An attacker who holds a hijacked session **and** the victim's second factor
can still create an external schedule. Step-up does not defend against a stolen factor. The schedule
is then visible in the owner's schedule list and to `manage_all` holders, every fire and delivery is
audited, and the owner-authority rule pauses it when the owner is disabled. TM-D30 makes the channel
cost a fresh MFA and a confirmation that is audited. It cannot prevent a user with full credentials
from mailing data they are entitled to send.

**Customer-facing effect.** No CEO decision is needed: TM-D30 adds a control and accepts no new
risk. An admin who adds an outside address to a schedule is asked for MFA once. On a new install the
allowed-domains list is empty (spec §8.4), so every address counts as external until the
administrator adds the company's domains. Until then, every schedule with an e-mail recipient steps
up. That is deliberate: the secure default nudges the admin to configure domains. The schedule
sheet's empty state should say so (T-0967).

## 3. Review of the conditional checks in `reports.yaml` (factory/T-0866 @ f23f297cd)

Sound as specified, with no change needed:

- **Run-read gate (modules/reports.md §6.6)** on `getReportRun`, `listReportRunRows`,
  `createReportExport` and `downloadReportExport` (creator path):
  - The 404 for another account's run does not say whether the run exists.
  - A fingerprint mismatch answers 409 `scope_changed_rerun`, and the fingerprint includes the token
    layer, so a narrower token or a revoked scope stops reads at once.
  - `manage_all` never opens a run.
  - `TestRunReadGateIsDeclaredOnEveryRunRead` asserts the declarations.
- **Delivery-row download (§7.2).**
  - The right comes from the DM-84 row written at fire time, never from the current recipient list.
  - `reports.export` and the enabled state are re-checked on every download.
  - Everyone else gets 404, or 401 when signed out.
  - `blob_key` never leaves the server.
  - Delete is creator-only.
  - These rules close the two attacks that matter: a guessed or leaked export ID, and a recipient
    added after the fire.
- **`owner=any` on `listReportSchedules`** answers 403 without `manage_all`, so it leaks nothing.
- **`reassignReportSchedule`** leaves the schedule paused, and the new owner must hold `reports.run`,
  `reports.export` and `reports.schedule`.
- **`runReportScheduleNow`** is owner-only.
- **`resumeReportSchedule`** is owner-only.

Defects. They must be fixed before T-0965 builds against the contract. T-0979 (api-engineer) carries
R1–R6; T-0892 defines the held-operation answer that R6 and SX-4 rely on.

| # | Sev | Where (`reports.yaml` @ f23f297cd) | Exploit sketch | Required fix | Test that must exist |
| --- | --- | --- | --- | --- | --- |
| R1 | **high** | `updateReportSchedule` description, line 550 ff.: "Changing another owner's schedule additionally needs reports.schedule.manage_all" | Technician T holds `reports.schedule` and `manage_all` over one OU. T edits a tenant-owner's domain-wide schedule: adds T's own account or mailbox, or swaps the definition for GRP-02 with all columns. The next fire runs under the **owner's** scope (DM-73.I1), so T receives data outside T's grant. This is a confused deputy: the spec's reassign rule exists precisely so that "a reassignment cannot widen what recipients receive without the new owner's act", and this edit path skips it. Spec §8.5 grants `manage_all` only "see, pause and reassign". | `update` is **owner-only**. A non-owner without `manage_all` gets 404; a `manage_all` holder, who can see the schedule, gets 403 with `errors[].code not_owner`. State the rule in the description and the header comment, and remove "Changing another owner's schedule additionally needs…". | Contract test: the description does not grant `manage_all` update. Build (T-0965): a `manage_all` non-owner's PUT is 403 and the stored version is unchanged. |
| R2 | medium | `deleteReportSchedule`, line 610 ff.: who may delete is not stated | If built as "any `reports.schedule` holder who knows the ID" or "any `manage_all` holder", one account can silently stop another's compliance delivery, because undo restores only for whoever holds undo. Spec §8.5 does not grant `manage_all` delete. | Owner-only. 404 for others, 403 `not_owner` for a `manage_all` holder. A `manage_all` holder stops a schedule with `pause`. | As R1, for DELETE. |
| R3 | medium | `getReportExport`, line 316 ff.: no binding stated | Any `reports.export` holder who enumerates or learns an export ID reads its row count, file name (it carries the report name), digest and expiry. That leaks the size of another account's or another scope's result. Its sibling `downloadReportExport` is bound; the record is not. | Same two paths as download: the creator, with the run-read gate passing, or the recipient of a Delivery row for this export. Everyone else gets 404. | Contract test asserts the binding text and the 404. Build: RP10 gains "another account holding `reports.export` gets 404 on GET export". |
| R4 | medium | `createReportSchedule` and `updateReportSchedule`: whose `reports.deliver.external` is checked at write time is not stated | After R1 the caller is always the owner, but write it down anyway: an implementation that checks the stored owner's permission instead of the caller's would let a reassigned or impersonated path ride the owner's grant. | "Checked against the caller, who is the owner (R1), at write time, and against the owner again at every fire (spec §8.4 check 3)." | Build: a caller without `reports.deliver.external` gets 403 `external_not_permitted` even when the owner field would qualify. |
| R5 | medium | `resumeReportSchedule`, line 676 ff.: no request body | The spec requires the new owner to resume "after seeing the recipient list". Through the API nothing proves that they saw it, and after a reassignment the **new owner's** scope, possibly wider, now flows to the old external recipients. | Resume takes a body with `confirmedExternal`, which must equal every external recipient (classified now). The SX-1 step-up applies when that set is non-empty. Use `400 external_not_confirmed` and `403 external_not_permitted` as on create. | Contract test: resume declares the body and the 400 and 403 codes. Build: resume after reassign without confirmation is refused. |
| R6 | low | create, update and resume (and the undo surface from T-0892): no 401 `step-up-required` response, and no "held for approval" outcome | Without a declared shape, clients cannot tell "MFA needed" from "signed out", and a held token write has no documented answer. | Declare `401` `StepUpRequired` (`shared/problems.yaml`) on create, update and resume. T-0892 defines the held-operation response it uses for every Action (SX-4). | Contract test: the three operations reference `StepUpRequired`. |

R1 is a design defect in the contract, not a code vulnerability: no handler exists yet. It is
therefore filed as contract rework (T-0979), not as a `bug`.

## 4. What each build ticket must prove

| Ticket | Must prove (test) |
| --- | --- |
| T-0980 kernel | A conditional-step-up Action submitted by a human without a fresh MFA is refused `step_up_required`. With a fresh MFA it plans. Submitted by a token, it is held `step_up`. An approval without step-up is refused. When the predicate is false, none of this applies. The catalogue test lists the conditional Actions. |
| T-0965 schedules | `Test_schedule_external_needs_step_up`: create, update, resume and undo with an external recipient are refused without step-up and accepted with it. The same writes with internal recipients only are accepted without it. A token create with an external recipient is held. The R1, R2 and R4 refusals hold. SX-5: an account recipient whose mail address is external fails alone. SX-6: an address made external by a later list change fails alone with its reason and the others are delivered. SX-8 audit fields are present. |
| T-0950 notify | `notify.settings.update` carries StepUp and its catalogue row. The SX-7 parser corpus refuses: <ul><li>a quoted local part (`"a@ok.example"@evil.example`);</li><li>a display name;</li><li>a source route;</li><li>an IP literal;</li><li>two `@`;</li><li>CR or LF;</li><li>a Unicode lookalike domain, which is classified after IDNA and is therefore external.</li></ul> `ok.example` does not admit `sub.ok.example` or `ok.example.evil.example`. |
| T-0967 UI | The schedule sheet asks for MFA only when an external recipient is present. The empty allowed-domains state explains why every address is external. |

## 5. Threat-model changes made with this review

- §5.15: new rows TM-TB15-T9 (a standing exfiltration channel through a schedule), T10 (a bypass by
  widening the allowed domains) and T11 (a non-owner edit that rides the owner's authority).
- §7.4: new row "Schedule writes that leave a schedule with an external recipient (TM-D30)" and
  "allowed recipient domains / SMTP relay changes".
- §16: new residual TM-R26.

## Changelog

- 2026-10-30 · T-0893. First version: DECISION TM-D30 (SX-1 to SX-8); contract review R1–R6 of
  `reports.yaml` @ f23f297cd; build proofs per ticket.
