---
name: service-proposal
description: Prepare a partner or customer proposal, SOW, SLA, discovery questionnaire, ManageEngine migration plan or onboarding checklist — from discovery to CEO approval. Nothing leaves the building without the CEO. Use for proposal tickets.
argument-hint: "[partner-slug]"
---

# Service proposal

We win ManageEngine customers by making switching feel safe. A proposal is the promise; the
migration plan is the proof we have thought it through. Owner: `service-manager` (with
`product-manager` on the migration mapping). Proposal tickets are reviewed by `factory-director`
(flow `proposal`), then go to the CEO. **Nothing leaves the building without CEO approval**
(`ceo-decisions`, category 6) — not a proposal, not a questionnaire, not an email draft.

## 1. Where things live — partner names are contained

| What | Path |
| --- | --- |
| Generic templates (this skill) | `.claude/skills/service-proposal/templates/` |
| Generic playbooks: migration playbook, support tiers, service SOPs | `knowledge/business/service/` |
| **Anything that names a partner or customer** — discovery answers, proposal, SOW, SLA, onboarding plan, sent log | `knowledge/business/partnerships/<partner-slug>/` only (CLAUDE.md rule 8) |

Tickets, decisions and notes refer to the partner by `<partner-slug>`, not by details of their
environment. Never copy partner documents into `factory/demos/previews/` — the decision links
to the file in `partnerships/`.

## 2. Procedure

1. **Read first**: `knowledge/business/partnerships/<partner-slug>/` (profile, history),
   `knowledge/memory/decisions-log.md` and `ceo-preferences.md` (commercial stances, anything
   already promised), the product's current state (`knowledge/memory/state-of-the-product.md`)
   and scope locks (`knowledge/business/scoping/`).
2. **Discovery** with `templates/discovery-questionnaire.md`. The generic questionnaire is
   approved by the CEO once, then reused unchanged; a tailored version is a new approval. Store
   answers as `partnerships/<partner-slug>/discovery.md`, each answer dated and attributed to
   its source (call notes, partner email — never invent an answer; unknown stays `[TODO]`).
3. **Fit check** against what exists: map each ManageEngine product, edition and workflow they
   use to feature IDs (`competitive-intel`) and to activeDIQ status in the parity matrix. Gaps
   are stated, not hidden: each gap gets "planned for <milestone> (not committed)" only if it
   is in an accepted milestone plan, otherwise "not available".
4. **Draft** `proposal.md` from `templates/proposal.md`; the SOW and SLA from their templates
   once the proposal direction is approved, or together if the CEO asked for a full pack.
5. **Self-check** (§5), advance the ticket → `factory-director` review.
6. **CEO approval** (after director review): file a `directional` decision —
   question "Send <document> to <partner-slug>?", options `a` Approve as written · `b` Approve
   with the changes in your note · `c` Do not send; preview = the path to the document; context
   ≤ 150 words: what is committed (scope, dates, service levels), what is a placeholder for the
   CEO, the main risks.
7. **After the answer**: apply changes; export (§6); the **CEO sends it** unless the answer says
   otherwise — the factory never emails partners. Record in
   `partnerships/<partner-slug>/log.md`: date, document, git commit of the sent version, sent
   by, decision ID.

## 3. What only the CEO fills in

- **Prices, discounts, payment terms** → `[PRICING — CEO]`. Never a number, not even
  "indicative". `market-analyst` pricing research may go into the decision context, never into
  the document as our price.
- **Service-level numbers** (response/resolution times, uptime for any hosted component,
  service credits) → the SLA template carries proposed defaults marked `[CEO]`; they are
  commitments and need the CEO's approval in the same decision.
- **Dates promised externally** (go-live, feature availability) → `[DATE — CEO]` unless the CEO
  already committed them (cite `decisions-log.md`).
- **Legal terms** (liability, IP, data processing, governing law) → `[LEGAL — CEO]`; we do not
  draft legal clauses.

## 4. The ManageEngine migration plan (in every customer proposal)

Phases, each with entry criteria, activities, exit criteria and owner (template in
`templates/proposal.md` §5):

1. **Discovery** — questionnaire answered; environment and pain points known.
2. **Inventory export** — export from ManageEngine what can be exported (templates, delegation
   roles, workflows, scheduled reports, alert profiles, self-service policies); what export
   paths ManageEngine supports is `[TODO]` until `market-analyst` has sourced it — say so in
   the plan.
3. **Mapping** — each item mapped to activeDIQ by feature ID; gaps and workarounds listed and
   accepted by the customer.
4. **Parallel run** — both systems live, activeDIQ read-heavy first; compare reports and audit
   output for agreed days. **Never two enforcers at once**: one password-policy filter, one
   self-service portal per user population, one owner of audit-policy GPO settings — the plan
   names which product owns each during the overlap (`ad-expert` reviews).
5. **Cutover** — pilot group, then waves; end-user switch (portal URL, logon-screen agent);
   ManageEngine jobs disabled; rollback trigger and window defined.
6. **Hypercare** — agreed duration, daily check-in, exit criteria (ticket volume, no S1/S2
   open), then decommission of ManageEngine agents and service accounts. Audit history stays
   available for the customer's retention period (archive or read-only instance) — never
   promise an audit-history import that has not been built and tested.

Time the cutover against the ManageEngine **renewal date** from discovery: the plan should end
hypercare before it, with buffer.

## 5. Self-check before advancing

- [ ] All partner-identifying content is under `partnerships/<partner-slug>/`.
- [ ] Every capability promised is shipped, or in an accepted milestone plan and labelled
      "planned, not committed"; gaps are stated.
- [ ] Pricing, SLA numbers, external dates and legal terms are CEO placeholders (§3).
- [ ] Every statement about ManageEngine follows `competitive-intel` §4 (factual, sourced,
      dated, never disparaging).
- [ ] Migration plan has all six phases with exit criteria, the never-two-enforcers rule, the
      renewal date, and audit-retention handling.
- [ ] Assumptions and risks are specific to this partner's discovery answers, not boilerplate.
- [ ] No secrets, no internal-only links, no `[UNVERIFIED]` claims in customer-facing text.

## 6. Export

No pandoc on this machine. Render the approved Markdown to HTML on `../design-system/tokens.css`
(light theme — documents go to paper) and print with
`npx --no-install playwright pdf file://<abs-path>.html <out>.pdf`. A Markdown→HTML converter
is a devops ticket after a licence-register check. PDFs are build output: keep them out of git
(or under the partner folder only if the CEO wants the sent copy archived).

## Templates

`templates/discovery-questionnaire.md` · `templates/proposal.md` · `templates/sow.md` ·
`templates/sla.md` · `templates/onboarding-checklist.md`
