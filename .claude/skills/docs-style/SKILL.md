---
name: docs-style
description: Write or review activeDIQ customer docs in docs/ — Diátaxis, voice and tone, templates (admin guide, end-user guide, API reference, release notes, migrating from ManageEngine), screenshots, versioning, review. Use for any docs ticket.
argument-hint: "[page or topic]"
---

# Docs style

Customer-facing documentation is part of the product: a ManageEngine admin judges us partly on
whether they can find the answer ("support articles can be somewhat difficult to find" is a
recurring complaint — `knowledge/business/market-research/manageengine-adselfservice-plus.md`
§5.3). Owner: `docs-writer`. Docs tickets are reviewed by `product-manager` (flow `docs`).

**Style is a CEO call made once.** `docs-writer` prepares an advisory decision with **two sample
pages** (the same how-to written in each candidate style, `ceo-decisions` §4). The answer goes to
`knowledge/memory/ceo-preferences.md`. Until then, **this skill is the default**; check
`ceo-preferences.md` first.

## 1. Diátaxis — every page is exactly one kind

| Kind | Reader's need | Shape | activeDIQ example |
| --- | --- | --- | --- |
| **Tutorial** | Learning, first time | A guided lesson with a guaranteed result on the lab/trial | "Your first hour: connect a domain and delegate password resets" |
| **How-to** | Doing a specific job | Goal → prerequisites → numbered steps → verify | "Bulk-create users from CSV" |
| **Reference** | Looking something up | Complete, dry, consistently structured | API endpoints, PowerShell cmdlets, permissions matrix, report catalogue, attribute map |
| **Explanation** | Understanding | Prose: why and how it works, trade-offs | "How activeDIQ writes to the right DC", "Tier-0 and the delegation model" |

Mixed page → split it and link. A how-to never stops to explain at length; it links the
explanation.

## 2. Layout of `docs/` (customer-facing; internal runbooks live in `knowledge/`)

```
docs/
  admin/{tutorials,how-to,reference,explanation}/   # admin guide
  end-user/                                         # self-service portal, enrollment, logon screen
  api/                                              # API reference (generated) + guides
  powershell/                                       # cmdlet reference (generated) + guides
  migration/manageengine/                           # Migrating from ManageEngine
  release-notes/<version>.md
  _media/<page-slug>/<nn>-<what>.png                # screenshots
```

The docs toolchain (static-site generator, search) is provisional until ADR-0001 and a devops
ticket; write plain Markdown with relative links so any generator works.

## 3. Voice and tone

- **Clear, calm, second person, present tense, active voice.** "You can reset passwords for
  users in OUs you are delegated." Not "Passwords may be reset by the operator."
- Lead with the point; one idea per sentence; sentences ≤ ~25 words. No hype ("seamless",
  "revolutionary", "simply", "just"), no apology, no jokes.
- **Exact names**: UI labels in **bold** as they appear on screen; attributes, cmdlets, paths,
  DNs and values in `code`. AD terms as Microsoft uses them (`sAMAccountName`, "fine-grained
  password policy", "AD Recycle Bin"). Product name: **activeDIQ** — always this casing.
- Warnings are calm and specific: what happens, to what, whether it is reversible.
  `> **Warning:** Disabling a Tier-0 account can lock administrators out. Confirm a second
  Tier-0 account is enabled first.` Use Note / Tip / Warning only.
- Inclusive, global English (US spelling for customer docs). No idioms; dates as 2026-10-02.
- No customer or partner names, no real people, no real domains — examples use
  the demo seed's domain `lab.activediq.test` (RFC 2606-reserved; `testing-playbook`), e.g.
  `CN=Jane Doe,OU=Sales,DC=lab,DC=activediq,DC=test`, so text matches the screenshots.
- Comparative statements about ManageEngine (migration guide only) follow `competitive-intel`
  §4: factual, sourced, dated, never disparaging.

## 4. Templates (in `templates/`)

| Template | For |
| --- | --- |
| `admin-how-to.md` | Admin guide how-to pages (the most common page) |
| `end-user-guide.md` | End-user pages: short, task-first, mobile-friendly, no admin jargon |
| `api-reference.md` | Hand-written API guide pages and the shape generated reference must have |
| `release-notes.md` | One file per version |
| `migrating-from-manageengine.md` | The migration guide skeleton, per ManageEngine product |

## 5. Screenshots

- **From the running product only**, demo seed loaded (`demo` skill) — never mockups, never a
  customer's data. Demo seed `lab/seed/demo` on `lab.activediq.test`.
- Captured by a Playwright script checked in beside the docs (`docs/_media/capture.spec.ts`,
  owned by `docs-writer`), so every image can be regenerated on each release. 1440×900
  viewport, `deviceScaleFactor: 2`, **one theme for all docs** (the CEO's style choice; default
  light — documents go to paper), browser clock frozen with `page.clock` so timestamps are
  stable.
- Crop to the region that matters. Annotate with the accent (`--sk-accent`) only: a 2 px
  rectangle and numbered callouts (mono, ①②③) that match the step numbers. No arrows and no
  blur — seed data has nothing to hide.
- Every image has alt text that states what it shows and why ("The impact preview listing 12
  users to disable, with 1 Tier-0 account flagged"). Filenames:
  `_media/<page-slug>/<nn>-<what>.png`.
- A UI change that invalidates a screenshot is a docs follow-up in the same ticket breakdown.

## 6. Versioning

- Docs live with the code and version with it; a page says what it applies to in frontmatter
  (`applies_to: ">=1.2"`). Behaviour removed → the page says "Removed in 1.4" and links the
  replacement for one major version.
- Every user-visible change ships its docs in the same milestone (DoD). Release notes are
  written from done tickets' two-line summaries, rewritten for customers.

## 7. Review flow

1. `docs-writer` drafts from the spec **and the running product** — verify every step by doing
   it on the lab. Record the build in frontmatter (`verified_on: <version/sha> YYYY-MM-DD`).
2. Technical accuracy consult: `ad-expert` for AD/Entra behaviour; `security-architect` for
   any page that configures privileges, credentials, MFA or hardening; `api-engineer` for API
   and PowerShell pages.
3. `product-manager` review: Diátaxis kind is right; matches the spec's ACs; voice per §3;
   screenshots current; links resolve.
4. **Publishing outside the building** (public site, PDF to a partner) is a CEO decision
   (`ceo-decisions`, category 6) — batch it per release, never per page.

## 8. Self-check

- [ ] One Diátaxis kind; title says the job ("Bulk-create users from CSV", not "Bulk operations").
- [ ] Every step done on the lab; `verified_on` set; expected results stated.
- [ ] Destructive steps carry a Warning and the impact preview screenshot.
- [ ] Required permissions listed (activeDIQ role and AD rights).
- [ ] Screenshots regenerated by the capture script; alt text present.
- [ ] No partner/customer names, no real domains; ManageEngine claims sourced and dated.
