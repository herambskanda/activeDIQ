---
name: competitive-intel
description: Use and maintain the ManageEngine research corpus and parity matrix — feature IDs, sourcing, [UNVERIFIED]/[TODO], comparative-claim rules for RFPs, battlecards, monthly refresh. Use for research tickets or before citing any competitor fact.
---

# Competitive intelligence

Everything we say about ManageEngine may end up in an RFP answer read by ManageEngine's own
customer. So every claim is **factual, sourced, dated, and never disparaging**. Owner:
`market-analyst`. Readers: every agent that cites a competitor. Research tickets are reviewed by
`factory-director`.

## 1. Where everything is

| What | Path |
| --- | --- |
| Per-product deep dives (editions, prices, architecture, **feature inventory with IDs**, UX notes, weaknesses, parity vs leapfrog) | `knowledge/business/market-research/manageengine-{admanager-plus,adaudit-plus,adselfservice-plus}.md` |
| AD360 suite, RecoveryManager Plus, M365 Manager Plus, Exchange Reporter Plus, commercial model | `knowledge/business/market-research/manageengine-ad360-suite-and-commercials.md` |
| Reviews, community sentiment, CVE history, switching drivers | `knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md` |
| Other vendors (Quest, Netwrix, Semperis, Cayosoft, Adaxes, Specops…), trends, personas | `knowledge/business/competitive-analysis/ad-management-market-landscape.md` |
| **Parity matrix** (once it exists) | `knowledge/business/competitive-analysis/feature-parity-matrix.md` |
| Internal battlecards | `knowledge/business/competitive-analysis/battlecards/<competitor>.md` |
| Customer-facing derivatives (one-pagers, RFP answers) — CEO-approved only | `knowledge/product/datasheets/` |
| Feasibility of building each capability | `knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` |

Several of these are still drafts with `[TODO]` sections. A `[TODO]` means "not researched",
never "absent". Read the section you need; never preload the corpus — ask `Explore` a precise
question ("Which ADSS IDs cover logon-screen reset, and which editions?").

## 2. Feature IDs

- Prefix per product: `ADM-` ADManager Plus · `ADA-` ADAudit Plus · `ADSS-` ADSelfService Plus
  · `RMP-` RecoveryManager Plus · `M365-` M365 Manager Plus · `ERP-` Exchange Reporter Plus ·
  `AD360-` suite-only. Three digits, zero-padded.
- **The ID is born in the product's inventory table** (§3 of its research file), in the row
  format `| ID | Module | Feature | What it does | Edition/add-on | Source |`.
- **IDs are stable forever.** Never renumber, never reuse. New feature → next free number at the
  end of its section (numbers need not be contiguous by section). A feature ManageEngine removes
  → keep the row, append `**Retired YYYY-MM-DD**` with the source. A duplicate → keep the lower
  ID, mark the other `**Merged into <ID>**`.
- Only `market-analyst` assigns IDs. Anyone else needing one files a `research` ticket.

## 3. Writing and updating research

- Every non-obvious claim carries an **inline URL** to the most primary source available:
  vendor docs/PDF/release notes > vendor marketing > independent review > forum > inference.
  Label inference explicitly: "(inference)".
- `[UNVERIFIED]` — a claim with a source you could not confirm (403 page, search snippet only,
  conflicting sources). `[TODO]` — not yet researched. Never upgrade either without a source.
- Frontmatter carries `sources_last_checked: YYYY-MM-DD`; bump it only for sections you actually
  re-checked, and note which in the Changelog section at the end of the file.
- Prices: list price, currency, unit, edition, "annual subscription" vs perpetual, and the date
  and URL. Say "list price before discounts".
- Absence: write "not documented in <source> as of <date>", never "does not support".
- Quotes from reviews: ≤ 1 sentence, attributed (site, reviewer as shown, date, URL).
- Do not edit another agent's in-progress draft (check the ticket); add a note or a ticket.

## 4. Comparative-claim rules — hard rules

1. **Factual**: describe what the product does, not what it is ("requires Domain Admin rights to
   push login agents [source]", not "insecure by design").
2. **Sourced** with an inline URL, and **dated** ("as of 2026-10-02").
3. **Never disparaging**: no adjectives about the competitor ("clunky", "outdated", "bloated").
   Let the fact speak. Quoting a customer's adjective is allowed internally, attributed.
4. **CVEs**: ID, CVSS, affected builds, fix build, date, advisory URL. No characterisation.
5. **Compare like with like**: same edition tier, same unit, same date.
6. **No claims about our own roadmap** as if shipped. Ours: "available in vX" or "planned".
7. Anything that leaves the building (datasheet, RFP answer, battlecard shared with a partner)
   is a CEO decision (`ceo-decisions`, category 6), with the document as the preview.

## 5. The parity matrix

`feature-parity-matrix.md` (create it only from a ticket that says so) has one row per feature
ID, in ID order:

| ID | Feature | ME edition | Must-have for switchers? | activeDIQ status | Spec | Milestone | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |

- `activeDIQ status` ∈ `parity` · `enhanced` · `planned` · `deferred` · `out of scope` · `[TODO]`.
- **Columns 1–4 belong to `market-analyst`**, 5–7 to `product-manager` (scope is the CEO's;
  `planned` requires a scope lock). Edit only your columns; the other owner's changes come by
  ticket.
- Every row's ID must resolve in a research file. A CI check may enforce this later.

## 6. Battlecards

Template: `battlecard-template.md` in this directory. One per competitor product, internal,
≤ 2 pages. Every "where we win" line pairs with a sourced fact; every "where they win" line is
honest — it is what our sellers will be hit with. Refresh with the monthly cycle.

## 7. Monthly refresh (research ticket, `market-analyst`; also on a major ManageEngine release)

Checklist: `refresh-checklist.md` in this directory. Outcome:

1. Each research file: new release-note entries, editions/prices, advisories, ratings re-checked;
   `sources_last_checked` bumped; Changelog entries added.
2. New features → new IDs (§2) and new matrix rows with status `[TODO]` for `product-manager`.
3. Parity-affecting changes (a new ME feature in a module we are building, a price move, a
   significant CVE) → a ticket for `product-manager` (scope impact) and a line in the refresh
   report.
4. Battlecards updated.
5. Report `knowledge/business/competitive-analysis/refresh-YYYY-MM.md`: ≤ 15 lines of what
   changed and why it matters, with links. If something is directional (e.g. ManageEngine drops
   price 30%), draft the decision via `ceo-decisions`; never assume the CEO wants to react.
