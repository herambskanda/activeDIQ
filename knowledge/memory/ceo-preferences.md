---
title: CEO preferences
updated: 2026-11-10
budget: 120 lines
---

# CEO preferences — how heramb wants to work

Newest first within each section. Every entry: date · preference · source. Use they/them for the
CEO unless they state otherwise.

## Working style
- 2026-11-10 · When the factory host was out of reach, they wanted M2c to keep moving on a second machine, and took the recommended "plan here, build later" over building on stale code. Away from the server, offer document-only work (specs, plans) that merges cleanly, not a second board. (off-board decision, decisions-log 2026-11-10)
- 2026-11-02 · Lab access, second time: took the recommended pool-scoped Proxmox token over building VMs by hand or deferring, answered on the board with no note. Two data points now (A-0025, D-0022): for lab hand-steps the default offer is a narrowly scoped, one-command-revocable worker authorisation, recommended first. Still lab-only; do not extrapolate to customer or production-like systems. (D-0022, notice D-0023)
- 2026-10-29 · Lab access: given the choice, they authorised workers ("workers may use WinRM on dc1 in the lab only") instead of doing the dc1 prep by hand. When a lab step needs a human, offer a scoped authorisation for workers as an option. Keep it lab-only. (A-0025)
- 2026-10-29 · Deferred the Entra sandbox tenant to after M1 ("can we do it in last after m1 is completed"). Don't file Entra-tenant actions during M1. Re-file once at M1 acceptance (T-0075, T-0441 parked in M2). (A-0026; A-0030 withdrawn 2026-10-30)
- 2026-10-09 · **Never publish activeDIQ material to the claude.ai Artifact site.** Visuals and docs live in the factory Library (board) in the board's own theme (tokens.css: monochrome + indigo). Source: architecture-diagram request.
- 2026-10-09 · Prefers transparency and control over the conservative option on public release: chose source-available BSL, publishing all of business/ and a personal owner over the recommended Apache-2.0 / keep-business-private / org. For leaving-the-building questions, offer the options but do not assume the cautious one wins. (D-0018)
- 2026-10-02 · With three clickable previews and a recommendation, the CEO took the recommended taste option (A · Ledger) on the board about 90 minutes after filing, with no note and no mix. On D-0005, which was option text only, they overrode the recommendation. Previews plus a reasoned recommendation get fast taste answers, so keep that format for T-0016 (docs) and T-0017 (video). (D-0012)
- 2026-10-02 · Took the recommended option on the four strategy questions (scope, deployment, platform, ambition) but **overrode it on brand**. They chose a separate brand over the recommended skenzeriq sub-brand, on the board, before the 72 h default ran out. Keep leading with a recommendation, but expect the CEO to override it on identity and taste. Those questions need real previews, not option text. (D-0001…D-0005)
- 2026-10-02 · Asks only for directional input: number of features, UI style, video style, documentation style, brand guidelines, demo acceptance. Everything else the factory decides. (kickoff brief)
- 2026-10-02 · Wants one simple contact surface showing what is happening and what needs them; near-real-time is enough. (kickoff brief)
- 2026-10-02 · Values live, visual views of the factory. They asked for a node-and-edge Agents graph that shows each agent with its model, effort and context, plus who talks to whom. Their standing instruction for it was "don't interrupt what's running". They accepted it as shipped ("awesome, we can proceed"). Fixes to factory tooling never stop workers that are running. (F-0001, 106c42d)
- 2026-10-02 · Wants the factory to demo the product at the end of a milestone; they judge good/bad and say what to change. (kickoff brief)
- 2026-08-12 · Values comprehension over impressive-looking code: architecture documented before implementation, ADRs, explainable modules. (../UEM/knowledge/business/strategy/product-strategy.md §3)
- 2026-08-12 · Prefers local web "studios" for decision loops (UEM domain-model studio on 127.0.0.1). (../UEM/.claude/skills/domain-model/SKILL.md)
- 2026-08-12 · Status reports in very few lines; no summaries of things they did not ask about. (../UEM/.claude/skills/domain-model/SKILL.md)

## Models and cost
- 2026-11-02 · A day after D-0016 they gave M1 every slot ("all slots go to M1 until M1 is accepted"), setting the hold themselves on the board. Finishing and accepting M1 comes before any M2a progress. Do not release held tickets for throughput. Ask about M2a again only at M1 acceptance. (T-1347)
- 2026-11-01 · On the date their "M2a only" hold ran out, they put finishing M1 (the lab proofs, the RC4 security fix) ahead of M2a speed. They gave the split as numbers in the answer note ("Resume M1/lab in 5 slot; keep 1 slots for M2a"), the reverse of the recommended 1-slot option. When an answer note gives numbers, apply the note over the option label and file a notice. When capacity is being split, offer the bolder split as an option too. (D-0016, notice D-0018)
- 2026-10-22 · On lab spend, took the free route (Developer Program sandbox) over a small paid tenant or deferring. They did not defer the least-privilege proof. Lead with free-if-eligible and give a priced fallback. Keep their hands-on steps to one command, with no credential pasting. (D-0001, current board)
- 2026-10-02 · **Nothing runs above `high` effort** (this replaces the kickoff's xhigh/max-on-escalation rule). Use Sonnet at high for most roles and Opus at high only for the important ones ("like yourself"). Daily run cap 300. They prefer more runs on cheaper settings over fewer runs at maximum effort. (CLI answer 2026-10-02)
- 2026-10-02 · Wanted 6 parallel worker slots and corrected the factory's cautious choice of 4. On throughput they lean towards more capacity, within the 300/day cap. When they ask to change a capacity setting without giving a number, ask for the number in one line. Don't pick a conservative value for them. (CLI, 2026-10-02)
- 2026-10-02 · Each working stretch stays under 300k tokens with a graceful handoff, never an abrupt stop. (kickoff brief)

## Product direction
- 2026-10-02 · activeDIQ stands on its own brand: "Own palette and identity, independent of skenzeriq" (the option they chose). Do not anchor activeDIQ's identity on consistency with skenzeriq. (D-0005)
- 2026-10-02 · Replace ADManager Plus first; hybrid (Entra/M365) from v1; self-hosted first but SaaS-ready; standalone from UEM for now; 5 signature enhancements, not 3 or 8 — ambitious but pilot-date-aware. (D-0001…D-0004)

## Taste
- 2026-10-02 · **activeDIQ looks like "Ledger"**: dense, light warm paper, cobalt `#0A5CB0`, IBM Plex Sans/Mono, labelled left rail, 32 px rows, flat hairlines and 2 px radii. Density and restraint win over distinctiveness; the impact preview and the Tier 0 states should be the loudest things on screen. Do not drift toward cards, soft shadows or loud accents (B and C were not chosen). (D-0012)
- 2026-10-02 · activeDIQ does **not** use the skenzeriq look (Electric Indigo, Geist, ink/paper). Its palette, type, mark and UI style come from the previews in T-0042. skenzeriq's design system stays the craft reference (grid, accessibility, patterns) and the brand for company documents. (D-0005, notice D-0008)

## Research and claims
- 2026-08-12 · External claims carry inline source URLs; unverified claims tagged [UNVERIFIED]; never guess competitor features. (../UEM/CLAUDE.md)
