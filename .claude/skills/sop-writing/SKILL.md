---
name: sop-writing
description: Write, rehearse and publish an activeDIQ SOP or runbook — template, safety rules for steps touching AD, lab rehearsal before publishing, locations (internal runbooks, service SOPs, customer docs/). Use for any SOP, runbook or procedure ticket.
argument-hint: "[procedure]"
---

# SOP writing

An SOP is a procedure someone will follow under pressure — often against a production domain,
sometimes at 2 a.m. during a cutover. It must work the first time, exactly as written. Owners:
`docs-writer` (product runbooks and customer procedures), `service-manager` (service SOPs:
onboarding, support, migration). Template: `template.md` in this directory.

## 1. Where it goes

| Kind | Audience | Path | Style |
| --- | --- | --- | --- |
| Engineering runbook (build, lab, release, demo env, incident) | factory agents | `knowledge/development/runbooks/<name>.md` | this skill |
| Service SOP (onboarding, support triage, migration steps, hypercare) | factory + partners' engineers | `knowledge/business/service/sops/<name>.md` | this skill |
| Customer procedure (install, upgrade, backup, DR, migration) | customer admins | `docs/admin/how-to/<name>.md` | this skill's rigour + `docs-style` voice and template |

Customer- or partner-specific variants (named topology, names, hostnames) live **only** under
`knowledge/business/partnerships/<partner>/` (CLAUDE.md rule 8). The generic SOP never names
them; it parameterises them (`<DC_HOST>`, `<SERVICE_ACCOUNT>`).

## 2. Write it

Fill every section of `template.md`. The rules that matter most:

1. **Numbered steps, one action each**, imperative ("Run", "Select", "Confirm"). Each step
   ends with an **Expected result** the operator can check — output text, a screen state, a
   count. A step with no checkable result is two steps or a bad step.
2. **Exact commands** in code blocks, copy-pasteable, with placeholders in `<ANGLE_CAPS>` defined
   in Prerequisites. No "etc.", no "as appropriate".
3. **Safe primitives in every command** (CLAUDE.md rule 5): PowerShell with parameters and
   splatting (`Get-ADUser -Identity $sam`), never `Invoke-Expression` or string-built commands;
   LDAP filters built by our tooling or written literally with no interpolated input; no SQL
   string concatenation; quote every shell variable.
4. **Steps that change a directory or a customer system** are marked **⚠ Change** and say what
   changes, on which objects, and whether it is reversible. Precede them with a check (dry run,
   impact preview, `-WhatIf`, a backup or snapshot step). Tier-0 objects (Domain Admins,
   AdminSDHolder-protected accounts, DCs, domain-linked GPOs) get an explicit confirmation step.
5. **Branches are explicit**: "If the result is X, go to step 9. Otherwise continue." No
   implicit judgement calls; where judgement is unavoidable, name who decides (Roles).
6. **No secrets.** Credentials come from the secret store by name ("the `adiq-lab-admin` entry
   in the local secret store"); never in the SOP, never in an example.
7. **Rollback** is written for every ⚠ Change step, and rehearsed like the rest.
8. **Time box**: expected duration per phase, and the point of no return (if any) stated in
   the Purpose section.

Ask `ad-expert` to review the AD-specific steps (replication, AdminSDHolder, Recycle Bin,
FGPP, audit policy). Anything touching credentials, privileges, DC-side components or the
password filter → `security-architect` consults before review, and the ticket is tagged
`security-sensitive`.

## 3. Rehearse before publishing — no exceptions

Every SOP is executed once, end to end, against the lab before it leaves `draft`:

1. Use the lab that matches the procedure (`testing-playbook`): the Samba AD lab
   (`make lab-up TIER=small`, `make lab-reset` afterwards) for LDAP-level procedures; the
   Windows lab for anything Windows-only (GPO, event logs, DC agent, password filter, logon
   agents). The Windows lab needs CEO approval — if it does not exist yet, the SOP stays
   `draft` with `rehearsal: blocked — <ticket or D-id>`.
2. Follow the SOP **literally**, as written, in a fresh session or by a different agent than the
   author when possible. Do not fix the procedure from memory while running it.
3. Record each step: pass / deviation. Any deviation → fix the text and re-run the affected
   steps (and everything after a ⚠ Change). Run the rollback section too.
4. Save the evidence (command output, screenshots) to `factory/demos/evidence/<ticket>/` and fill
   the Rehearsal record table in the SOP: date, lab and tier, product build, who (agent + run
   ID), result, evidence path.
5. Only then set `status: review` and advance the ticket.

Re-rehearse when the product version the SOP depends on changes in a way that touches its steps,
and at least once per major release for customer procedures.

## 4. Review and publish

- Flow: SOP tickets are type `docs` → reviewed by `product-manager`. The reviewer checks: every
  step has an expected result; every ⚠ Change has a pre-check and a rollback; the rehearsal
  record is filled and the evidence exists; no secrets or partner names; safe primitives.
- Internal SOPs become `accepted` after a human read (`knowledge/README.md`). Customer-facing
  ones are published with the docs release, which needs a CEO decision (`docs-style` §7).
- Every change after publishing: bump `updated`, add a Revision history line, re-rehearse the
  changed steps.
