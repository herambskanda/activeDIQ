---
title: Conventions in force
updated: 2026-10-02
budget: 120 lines
---

# Conventions in force

- Knowledge base: frontmatter, status ladder, sourcing, ADR ladder, feature IDs — knowledge/README.md.
- Everything is a ticket. Factory state changes only through `factory/bin/factory`; never edit factory/state/ by hand.
- IDs: tickets `T-0001`, decisions `D-0001`, CEO actions `A-0001`, feedback `F-0001`, epics `E-001`, milestones `M1`, runs `R-…`.
- Ticket branches `factory/T-0001`; conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`); workers never commit to main and never push; the dispatcher merges after QA.
- ManageEngine parity IDs: `ADM-` ADManager Plus · `ADA-` ADAudit Plus · `ADSS-` ADSelfService Plus · `RMP-` RecoveryManager Plus · `M365-` M365 Manager Plus · `ERP-` Exchange Reporter Plus · `AD360-` suite.
- Handoffs: factory/handoffs/<ticket>/<timestamp>.md (template factory/templates/handoff.md); session handoffs under factory/handoffs/session-<id>/.
- Previews for CEO decisions: factory/demos/previews/<decision-id>/ (HTML mockups use ../design-system/tokens.css).
- QA evidence: factory/demos/evidence/<ticket>/.
- Prototypes: garage/<name>/ with a README stating owner and expiry date.
- People whose pronouns are unknown are referred to as they/them.
