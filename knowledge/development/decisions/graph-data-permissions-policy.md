---
title: Tenant-wide Graph data permissions on the connector app — decision prep (TM-D5a follow-up)
date: 2026-10-26
updated: 2026-10-26
status: accepted
owner: security-architect
kind: decision-prep
ticket: T-0303
decision: D-0007
implemented_by: T-0369
---

# Tenant-wide Graph data permissions on the connector app

**Outcome (2026-10-26):** the factory-director accepted **option A (deny)** at review of T-0303;
notice **D-0007** (acknowledged by the CEO). **T-0369** implemented it: seven exact-value entries in
`denyPatterns` (`internal/connector/rights/policy_entra.go`), tests, threat-model §6.6 and the
TM-F-RIGHTS row. `Sites.Manage.All` is still pending lab G15.

## The question

TM-D5a ([threat-model.md §6.6](../architecture/threat-model.md)) put `full_access_as_app`,
`Exchange.ManageAsApp` and `Sites.FullControl.All` on the EV3 deny list. Tenant-wide *data*
permissions on Graph itself (`Mail.ReadWrite`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`) are
the same class, but today they fall to **EV5 warn** (`EXCESSIVE_RIGHT`): the allow rows do not
contain them, and `entra.go` (the `case !onGraph || !allowed[…]` branch) reports every
unlisted grant as a warning. Should they be blocked?

## Recommendation (one line)

**Deny.** Add the data-permission set below to the EV3 deny list, overridable only through the
existing TM-D1 override. No v1 feature needs any of them, so an allow-list exception is
machinery for a case that does not exist. T-0302 follow-up implements it as exact-value entries
in `denyPatterns` (no new matching logic). Implemented by T-0369.

## 1. The permissions: blast radius and legitimate need

"Legitimate need" is measured against the v1 scope in `knowledge/product` / the M2 plan: no v1
feature reads or writes mailbox content or SharePoint/OneDrive content. ADM-026/ADM-070 and the
ADM-045 mailbox block go through the Exchange PowerShell helper, which is the `Exchange.ManageAsApp`
path TM-D5a already refuses for the Graph credential (TM-Q25 requires a separate certificate and
ideally a separate app registration).

| Permission | What it does with no signed-in user | Blast radius | Needed by a v1 connector? |
| --- | --- | --- | --- |
| `Mail.ReadWrite` | "create, read, update, and delete email in all mailboxes … Doesn't include permission to send mail" ([Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)) | Every mailbox in the tenant, including those of Global Administrators and help-desk staff. Read: password-reset and MFA-enrolment mail, invitation links, secrets sent by mail. Write: inbox rules and message edits that hide security alerts. Not a path to a directory role by itself, but it reaches the accounts that hold one | **Never** in v1 |
| `Files.ReadWrite.All` | Read and write all files in OneDrive and SharePoint `[UNVERIFIED — description not read in the permissions reference; the page is 578k characters]` | Every user's OneDrive and every document library: documents, scripts and credential files of administrators; tampering with deployed scripts or templates | **Never** in v1. The ADM-045 NTFS block is a file-server agent (FEAS §1.4), not OneDrive |
| `Sites.ReadWrite.All` | Edit or delete items in all site collections `[UNVERIFIED — as above]` | All SharePoint sites. Managing site permissions requires `Sites.FullControl.All` (or Selected+FullControl/Owner) per [Selected permissions](https://learn.microsoft.com/en-us/graph/permissions-selected-overview), so this one is content-only `[UNVERIFIED — that it cannot grant app access is inferred from that table]`, so no self-escalation. Content only | **Never** in v1 |

Siblings that share the shape (same abuse, same absence of v1 need):

| Permission | Basis |
| --- | --- |
| `Mail-Advanced.ReadWrite.All`, `MailboxItem.ReadWrite.All`, `MailboxItem.ImportExport.All` | Listed on the same Microsoft page as create/read/update/delete or export-and-import of all users' mailbox items ([Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)) |
| `Mail.Send` | "send mail as any user" (same page). It is a phishing and password-reset-social-engineering primitive as any user |
| `Sites.Manage.All` | `[UNVERIFIED — name and description recalled, not read]`; confirm in lab G15 before adding |

Read-only counterparts (`Mail.Read`, `Files.Read.All`, `Sites.Read.All`, `Mail.ReadBasic.All`)
**stay EV5 warn**. They are confidentiality-only, a customer may hold them on a shared registration
for reporting tools, and blocking them would teach the "override by habit" behaviour §6.6 already
rejected for all non-Graph roles. The EV5 finding stays visible in the health check.

## 2. Scoping reality (why "unscoped grant" is the risk)

- **Mail.** Exchange RBAC for Applications can give an app `Application Mail.ReadWrite` limited to a
  management scope or administrative unit, but "permission consents are additive": an unscoped
  Entra grant of the same permission "results in no effective resource scoping" ([Application RBAC FAQ](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)).
  So an Entra-consented `Mail.ReadWrite` is by definition the tenant-wide form, and that is what the
  rule targets. A scoped Exchange-side assignment is invisible to Graph (TM-R20) and is not affected.
- **Sites and files.** `Sites.Selected` and `Files.SelectedOperations.Selected` give nothing until a
  site owner assigns a role, "Selected scopes require an explicit assignment action" ([Selected permissions](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)).
  They stay allowed, as TM-D5a already says. Customers have a scoped alternative for every
  case, which keeps the customer impact of a block low.

## 3. Options compared

| | A. Deny (block) | B. Warn (status quo) | C. Deny unless allow-listed |
| --- | --- | --- | --- |
| Behaviour | EV3 `ENTRA_DENY_LIST_PERMISSION` block at onboarding and in every health check; override via TM-D1 (explicit, audited, permanent banner) | EV5 `EXCESSIVE_RIGHT` warning; activation proceeds | Block unless the customer admin lists the permission as accepted for this connection (a per-connection exception, audited) |
| Customer impact | A customer whose registration carries `Mail.ReadWrite` etc. (a registration shared with a backup, migration or archiving tool) must split the registration (our guidance: one registration per product, **no owners**, §6.6) or use the override. One extra step at onboarding; none after | None. The warning is the one customers already see for `Directory.Read.All` extras and will not read | Same friction as A plus a UI and a stored exception record that must itself be threat-modelled (who may add one? a Tier-2 help-desk role must not) |
| Security | Strongest. Compromise of the activeDIQ Graph credential (TM-TB17-T5, a stolen certificate) cannot read or alter any mailbox or document, so activeDIQ is not a path to a tenant's mail | Weakest. The credential holder reaches all mail and files, and our own health check says "warn" | Same as A while no exception exists; an exception reopens A's gap with a logged justification |
| Engineering cost | Eight entries in `denyPatterns`, tests alongside TestTMD5aDenyListOnAnyResource. No logic change | None | New exception data model, API, UI, audit event, RBAC, fitness test. Not justified when the legitimate need is zero |
| Product story | "activeDIQ cannot read your mail or files, and onboarding proves it" is checkable and sellable against ManageEngine's tenant-wide M365 grants `[UNVERIFIED — no research file cited here for ManageEngine's Graph scopes]` | Contradicts the story: the warning would say the same thing about a mail-reading app and an unused read right | Story holds only with the caveat of exceptions |
| Risk | Override by habit (see the rejected all-roles block). Mitigated by the narrow, named set and by the override's permanent banner | Silent drift to Tier-0-adjacent reach | Exceptions accumulate |

**Why not C.** An allow-list exception is the right tool when some customers legitimately need the
permission. Here no v1 feature does, and a feature that needs one later arrives through the RT-4
process (new Graph permission = new §6.6 row with a reason), which is the allow-list. C would be a
second, weaker allow path next to the one the threat model already requires.

## 4. What the director decided, and what T-0369 implements

**Decision (accepted 2026-10-26, D-0007):** option A for the set in §1 (the three named permissions plus
`Mail.Send`, `Mail-Advanced.ReadWrite.All`, `MailboxItem.ReadWrite.All`, `MailboxItem.ImportExport.All`;
`Sites.Manage.All` once lab G15 confirms the name), leaving read-only counterparts at EV5 warn.
This is a risk-acceptance on customer experience (a block where today there is a warning), so
it is the director's, not ours. It needs no CEO question: it is a security default with an existing override, not
scope, money or brand.

**Implementation: T-0369** (directory-engineer, security-sensitive, P2, done 2026-10-26) did steps 1–3 with
these seven values. No onboarding guide exists yet, so the customer guidance of step 3 lives in
threat-model §6.6. Step 4 (lab G15, `Sites.Manage.All`) remains open. The implementation ticket had to:

1. Add the values to `denyPatterns` in `internal/connector/rights/policy_entra.go`, matched on any
   resource and case-insensitively, exactly as TM-D5a's three values.
2. Extend `TestDenyListMatching` and `TestTMD5aDenyListOnAnyResource` with each value on Graph and on
   another resource; assert `Mail.Read`, `Files.Read.All`, `Sites.Read.All`, `Sites.Selected`,
   `Files.SelectedOperations.Selected` and `Exchange.ManageAsApp.Extra` remain EV5 warn (or allowed).
3. Update threat-model §6.6 (deny list text; replace the "gap is T-0303" sentence), the TM-F-RIGHTS
   fitness row, and add a changelog line; the onboarding guide must tell the customer to use a
   dedicated registration or scope Exchange access through RBAC for Applications.
4. Lab G15 records the exact Graph role ids and names (`Sites.Manage.All` in particular).

**Not taken (kept for the record):** had the director rejected, B would have stayed, and §6.6 would
have recorded a TM-R residual: "an activeDIQ credential thief reaches all mail and files if the
customer consented those".

## Residuals under the recommendation

- A customer who overrides (TM-D1) reopens the gap and the product says so (permanent banner).
- Exchange-side scoped or unscoped role assignments to the service principal are invisible to Graph (TM-R20).
- Names of the sibling permissions rest on Microsoft's Exchange RBAC page; the full permissions
  reference was not read end to end (`[UNVERIFIED]` items above).
