---
title: M2c delivery plan — checkpoint 2c "Hybrid and import" ticket plan
date: 2026-11-11
updated: 2026-11-11
status: draft
owner: project-manager
---

# M2c delivery plan: checkpoint 2c "Hybrid and import"

Grooming of checkpoint 2c ([roadmap-skeleton.md](roadmap-skeleton.md) row 2c, exit criterion 6) into
a ticket plan, as a document: this machine has no factory board (CEO decision 2026-11-10,
[decisions-log](../../memory/decisions-log.md)). Keys `C-01`…`C-110` are plan keys. The director turns
them into tickets on the server board at merge, with `depends_on` rewritten from keys to T-ids. **This is
a backlog, not a start signal:** the server's M1-focus hold stands (§3). Format follows [m2-plan.md](m2-plan.md).

Inputs: [E2.7](../../product/specs/e2-7-hybrid-provisioning.md) and
[e2-7a](../../product/specs/e2-7a-entra-inventory-sync.md) (both advanced), [E2.6](../../product/specs/e2-6-report-builder.md)
(advanced), [E2.11](../../product/specs/e2-11-migration-importer.md) (status `draft`, dated 2026-10-28, **no
review on file**), the round 3 follow-up lists in the
[architecture review](../../product/specs/reviews/2026-11-11-m2c-architecture-review.md) and the
[security review](../../product/specs/reviews/2026-11-11-m2c-security-review.md). Post-erratum names are used
(`Descriptor.Waits`, `WaitCondition`, step kind `wait`; Resume writes a fresh row on a new approval; re-sync caps apply to
Check now only; the licensed-group rule A3-m3; E2.6 presence operators, time-zone rule and no custom labels).
Off-board items are cited as `CO-n` = row n of [m2c-board-carryover.md](m2c-board-carryover.md) and not duplicated:
CO-2 (`ms-DS-ConsistencyGuid` into `guarded-v1`, P1 bug), CO-3 (OQ-C1, dormant), CO-4 (ADMP timing research),
CO-5 (TM §6.6/§6.4 rows), CO-6 (lab G11), CO-7 (file E2.7/E2.6 as spec tickets), CO-8 (AD-synced licensed groups outside a
hybrid request). The spec-errata work is under way on this branch and is not ticketed.

## 1. 2c epics and their slice

| Roadmap | Board | 2c slice | Parity refs (matrix IDs) | Not cut (destination) |
|---|---|---|---|---|
| E2.7 + e2-7a | E-013 | Entra tenant connection, rotation, writable groups; Entra delta sync and three datasets; the one hybrid create with waiting continuation; licence and group steps; SOA view | ADM-159, I360-003, ADM-027 (narrowed), ADM-161, M365-005, ADM-164, M365-007, ADM-169 (minimal), ADM-131 (enforcement only) | Slice 2c-b: ADM-162, CSV licences, licence to a group, OU filter. Post-2c: ADM-009, ADM-160. OQ-C1 dormant (CO-3) |
| E2.6 builder | E-012 | Typed builder, grouping and charts, preview, definition store and sharing, act on results, importer landing | ADM-097, ADM-096, ADM-098, ADM-099–102 (inherited or partial), ADA-101 (partial) | ADM-103 widgets (FB-9, later) |
| E2.11 (ADMP) | E-017 | Review the draft; intake (file route and DB-dump route), hostile-file limits, classifier, fidelity report, proposals and step-up apply, technician mapping, report and schedule crosswalk | Playbook IDs MIG-02, 03, 05, 06, 16 (MIG-04 is E2.3). No matrix IDs | MIG-01 discovery, MIG-10 comparator, MIG-14 ownership switch (2d, roadmap row 2d); §8 lifecycle limits and AC-26–28 (E2.9, 2d); live-DB and API v2 routes (after the dump route proves the schema) |

Build tickets carry `--parity` from the 2c column. Specific rows appear in brackets in §6.

## 2. How the checkpoint is cut and decisions made in this plan

**Demo (roadmap 2c, exit criterion 6).** One flow creates an AD user with an M365 licence and groups; a lab ADMP 8043
configuration is imported with every item classified in the fidelity report; the report builder.

1. **Architecture first, each with its fitness ticket.** An ADR or amendment is `accepted` only when its fitness runs in CI.

   | Decision | Ticket | Fitness / proof ticket |
   |---|---|---|
   | ADR-0005 amendment (waits, coupled groups, outcomes, Resume, activation digest) | C-04 | C-05 (O4), C-06 (O8, O5) |
   | ADR-0004 rule 14 amendment (operation-level routes) | C-07 | C-08 (A15) |
   | ADR-0012 superseding ADR-0010 (FB-3b; ADR-0010 gets `superseded_by` on ratification) | C-16 | C-17 (RP12, RP13) |
   | reports.md amendment (FB-3a, two parts) | C-18, C-19 | C-20 (review and RP-B1…3 definitions), C-74 (RP-B1, RP-B2), C-84 (RP-B3) |
   | ADR-0011 amendment (FB-6a) | C-22 | C-78 (SE3-style test, built with the change) |
   | Connector contract revision (§14.4, e2-7a) | C-11 | C-12 (fake Graph), C-13 (conformance cases) |
   | E2.11 module design | C-27 | C-28 (allow/deny-list, fuzz-gate, no-script-route checks) |

   Domain-model, MAP-1 and SEC-1 tickets (C-09, C-10, C-14, C-15, C-21) are documents; their proof is the build tickets' tests.
2. **Three lanes after a shared architecture front.** Lane H (hybrid) is the longest and holds the demo's first sentence. Lane R (builder) shares only
   the dataset Boot rule (C-71) and the Entra scope roots with lane H. Lane M (import) starts with the review E2.11 never had.
3. **The kernel change is split in two.** C-31 (coupled groups, outcome names, windows) then C-32 (the `wait` step, `Descriptor.Waits`, the sweeper
   exemption), because both edit `platform/operation` and each is a full session.
4. **The dataset Boot rule sits in the reports lane** (C-71, e2-7a follow-up 3), so a dataset cannot register before its scope roots render.
5. **No cloud claim from Samba alone.** The AD half runs on Samba and the cloud half on fake Graph (tier F) in CI. Tiers E and H need the Entra sandbox
   (A-0026) and Entra Connect on the Windows lab; those proofs are C-66 and are marked blocked-by-action. Graph behaviours stay `[UNVERIFIED]` until C-65.
6. **Pre-cut check on the server board.** This checkout is the 2026-11-02 snapshot. `internal/modules/connections` already holds attestation, HybridLink and
   reconfirm code, and `connector/graph` holds the assertion. Before filing, shrink C-33/C-34 and C-38 to the delta against server main and parked tickets
   T-0075, T-0119, T-0183, T-0441 (X4).
7. **Order of the 2a/2b inputs.** External dependencies, not planned here: **X1** T-1131 (Entra scope roots, `include_correlated`, E-011);
   **X2** the 2b `objects` group-membership and user-update Actions and the grid bulk bar; **X3** 2a `reportsql`, export encoders, schedules and the connection model
   (T-0075, T-0101–T-0104, T-0119, T-0093); **X4** see 6; **A-0026** Entra sandbox; **A-0036** ADMP trial.
8. **Status at filing.** All rows are `backlog`; grooming promotes a row when its dependencies are done. Rows with no dependency (and so the first promotable set when
   the hold lifts): C-01, C-02, C-04, C-07, C-11, C-16, C-22, C-23, C-24, C-25, C-26, C-61, C-110.

**Sizes.** S under half a session; M about one session at ~150k context; L a full session near the budget. Nothing larger survives: bigger items were split
(§6 notes where an L may split again at pickup). Priorities: P1 critical path to the 2c demo; P2 in 2c, off the path; P3 first to cut.

## 3. Critical path, parallel lanes, and the hold

**Critical path to the demo (11 deep, as m2-plan accepts for inherent order):**
C-04 → C-05 → C-31 → C-32 → C-44 → C-48 → C-49 → C-51 → C-53 → C-66 → C-109 (ADR amendment, O4 fitness, kernel, wait step, HybridRequest, evaluator, binding, Resume, Undo,
lab proof, QA). C-66 is also blocked by action A-0026, so the calendar path ends at the CEO's action, not the code.

- **Lane H parallel work:** connection C-33 → C-34 → C-35; writable groups C-36, C-37; sync C-38 → C-39 → C-40; writes C-41 → C-42; all join at C-45/C-47/C-48.
- **Lane R (9 deep):** C-16 → C-17 → C-67 → C-70 → C-72 → C-86 → C-89 → C-90 → C-109; grouping side C-18 → C-19 → C-20 → C-68.
- **Lane M (12 deep incl. reviews):** C-01/C-02 → C-03 → C-27 → C-92 → C-94 → C-95 → C-97 → C-98 → C-101 → C-103 → C-105 → C-109. C-94, C-95 and everything after wait on
  C-29 (ADMP DB schema) and so on A-0036; only C-92, C-93, C-100, C-102 and C-104 can finish without it.
- **UI lane:** designs C-61 and C-110 have no dependencies and C-102 only C-03; they unblock C-62/C-63, C-87–C-90 and C-103.
- **Same-module sets (never co-scheduled):** `connections` {C-33, C-34, C-35, C-37}; `sync` {C-38, C-39, C-40}; Graph provider {C-41, C-42}; `objects` hybrid
  {C-44…C-51, C-53}; `reportsql` {C-67, C-68, C-70, C-73}; `platform/operation` {C-31, C-32}; domain-model.md {C-09, C-10, C-21}; reports.md {C-18, C-19}.

**What can run before M1 is accepted without conflicting with the hold:** none of the build, test, lab or UI tickets, and none of the C-29/C-30/C-64–C-66/C-105 lab
work (also blocked by action). Every ticket in this plan, including ADR drafts, would take a server worker slot, and the hold gives every slot to M1. The only
candidates are the document-only architecture drafts with no dependency: C-01, C-02, C-04, C-07, C-11, C-16, C-22. They could be drafted off-board on this branch as the
specs were, which uses no server slot (ratification and fitness still happen on the server). That extends the off-board precedent, so **the CEO decides**; the
recommendation is to leave them for the server when the hold lifts, except C-01/C-02 (the E2.11 reviews, cheap, and they unblock the whole importer lane).

## 4. Risks and items for the director

| Risk | Likelihood × impact | Mitigation / owner |
|---|---|---|
| solution-architect and security-architect are the bottleneck: 10 architecture tickets and 6 reviews or rulings before the first build | High × high | Order by P1. Draft ADRs in parallel across the three lanes. The director may split C-04 into two amendments if the draft passes 150k |
| C-04 changes the kernel for every Operation (2d workflows, JML and approvals reuse it) | Medium × high | Fitness lands first (C-05, C-06). C-31/C-32 gate on them. security-architect confirms H3-m1 (C-15) |
| A-0026 and A-0036 are CEO actions, deferred until M1 acceptance. C-66 and C-105 are the demo proof | High × high | Re-file both at M1 acceptance (ceo-preferences). C-64/C-65 need A-0026 only; C-29/C-30 need A-0036 only. Tier F proof runs without them |
| E2.11 was never reviewed. The draft may reopen scope (routes, ownership lock, EULA) | Medium × high | C-01/C-02/C-03 first. E2.11 build rows are Ready in content only after C-03 |
| X1 (T-1131) and X2 (2b Actions) may not be done when 2c starts. Act-on-results, licence/group Actions, SOA badge and Entra datasets need them | Medium × high | Director confirms their state at filing. Without X2, C-41 and C-79 cannot ship a live control (no dead buttons) |
| ADMP EULA review for the lab installers is `[TODO]` (migration playbook §9) | Medium × medium | C-29 records the finding. If counsel is needed, director raises it to the CEO (legal) |
| Many Graph behaviours are `[UNVERIFIED]` (delta field set, group `assignedLicenses`, Cloud Sync SID, nested PIM refusal) | High × medium | C-65 probes. C-12 tags unverified behaviour so tests do not harden a guess |
| Plan sizes assume server main matches the spec's reading (§2 item 6) | Medium × medium | Pre-cut check; shrink, do not duplicate |

**For the director to file or decide (nothing here is a CEO question except Q3):**
- File CO-2 as P1 before C-43, and CO-5, CO-6, CO-8 as listed. CO-4 informs C-61 and the demo script only.
- CEO actions behind this plan: A-0026, A-0036 (above). Q3 (pilot at 2c or exit) and the 2c-build pentest (D-0005) are not ticketed here: they follow the build.
- Whether to run the §3 document-only drafts early.

## 5. Tickets

Type · owner; `sec` = tag `security-sensitive` (adds security-architect review). Size S/M/L. Epic E-013 hybrid, E-012 builder, E-017 import; all M2.
`A-n` = blocked by CEO action. H = E2.7/e2-7a ACs, B = E2.6 ACs (AC-Bnn), M = E2.11 ACs.

| Key | Title | Type · owner | P | Epic | Size | Depends on |
|---|---|---|---|---|---|---|
| C-01 | Review the E2.11 importer spec: architecture, module fit, pipeline use | spec · solution-architect | P1 | E-017 | S | — |
| C-02 | Review the E2.11 importer spec: allow/deny lists, applier check, limits, ownership lock | spec · security-architect · sec | P1 | E-017 | M | — |
| C-03 | Revise E2.11 after review: cut to 2c, cite E2.6 §11.2 (FB-10), carve §8 out to 2d | spec · product-manager | P1 | E-017 | S | C-01, C-02 |
| C-04 | Amend ADR-0005: waits, coupled groups, outcome names, Resume, activation digest, plan-time authority | spec · solution-architect · sec | P1 | E-013 | L | — |
| C-05 | Fitness O4: `transitions` block and property test for the new edges | test · backend-engineer | P1 | E-013 | M | C-04 |
| C-06 | Fitness O8 cases (coupled block, expiry, sweeper exemption, supersede, carry-over) and O5 declared-wait case | test · backend-engineer | P1 | E-013 | M | C-05 |
| C-07 | Amend ADR-0004 rule 14: operation-level routes for multi-family Operations | spec · solution-architect | P2 | E-013 | S | — |
| C-08 | Fitness A15 extended to the operation-level routes | test · api-engineer | P2 | E-013 | S | C-07 |
| C-09 | Domain model for hybrid: HybridRequest, coupled/wait steps, `cloud_reason`, DM-21/24/33/50/80 | spec · ad-expert | P1 | E-013 | M | C-04 |
| C-10 | Domain model for Entra inventory: DM-16 rows and cursors, LicenceSku, DM-70 datasets | spec · ad-expert | P1 | E-013 | M | C-09 |
| C-11 | Revise the connector contract: Entra WriteKinds, membership touched set, not-visible and ambiguous outcomes, targeted re-sync, host pin and `tid` | spec · solution-architect | P1 | E-013 | M | — |
| C-12 | Build the tier-F fake Graph harness (delta, 429, members/$ref, assignLicense, SKUs, clock) | test · test-engineer | P1 | E-013 | M | C-11 |
| C-13 | Add Entra write conformance cases (touched set, not-visible retry, ambiguous outcome, property guard) | test · directory-engineer · sec | P1 | E-013 | M | C-11, C-12 |
| C-14 | MAP-1: blueprint rows for `objects` and `sync`, new `modules/m365.md` | spec · solution-architect | P2 | E-013 | S | C-04, C-10 |
| C-15 | SEC-1: TM-F-HYBRID wait-window cases; confirm H3-m1 Resume window and A3-m3 licence rule | spec · security-architect · sec | P1 | E-013 | M | C-04 |
| C-16 | Write ADR-0012 superseding ADR-0010 (match count, preview class, group rows, run identity) | spec · solution-architect · sec | P1 | E-012 | M | — |
| C-17 | Fitness RP12 (no `CompileCount`, no second count) and RP13 (preview supersede and expiry) | test · reporting-engineer · sec | P1 | E-012 | M | C-16 |
| C-18 | Amend reports.md part 1: definition store, namespace, Actions, EP-7 kinds, `ActionSubject`, validate-only, field read permission | spec · solution-architect | P1 | E-012 | M | C-16 |
| C-19 | Amend reports.md part 2: grouping nodes, flags, Unknown, presence operators, zone rule, label limit, refusal writer, Boot rule | spec · solution-architect | P1 | E-012 | M | C-18 |
| C-20 | Review the grouping renderer; define RP-B1, RP-B2, RP-B3 | spec · security-architect · sec | P1 | E-012 | M | C-19 |
| C-21 | Domain model for reports: DM-71, DM-72, DM-34, Q5 | spec · ad-expert | P1 | E-012 | S | C-16 |
| C-22 | Amend ADR-0011: caller-named permission on `inventory.Search` (FB-6a) | spec · solution-architect | P2 | E-012 | S | — |
| C-23 | Design note and blueprint row for `inventory.ResolveIdentifiers` (FB-6b) | spec · solution-architect | P3 | E-012 | S | — |
| C-24 | Rule on the `audit.events` dataset columns and erasure (FB-5) | spec · security-architect | P3 | E-012 | S | — |
| C-25 | Specify sync-set additions: who adds which attribute, backfill, freshness label (FB-8) | spec · product-manager | P2 | E-012 | S | — |
| C-26 | Research ME custom-report mechanics: operators, limits, cache, delegation (FB-1) | research · market-analyst | P3 | E-012 | S | — |
| C-27 | Design the `migration` module: job state machine, quarantine, proposal store, blueprint row | spec · solution-architect · sec | P1 | E-017 | M | C-03 |
| C-28 | Add migration fitness: allow/deny-list CI check, fuzz-target gate, no script-execution route | test · devops-engineer · sec | P1 | E-017 | M | C-27 |
| C-29 | Install the lab ADMP 8043; extract the DB schema and table/column allow-list; record the EULA finding | spike · directory-engineer | P1 | E-017 | M | A-0036 |
| C-30 | ADMP lab baselines T21–T25, custom-report and schedule fixtures, technician-report formats | research · market-analyst | P2 | E-017 | M | A-0036 |
| C-31 | Kernel: coupled item groups, widened `partially_succeeded`, `cloud_reason`, `plan_valid_until` vs `approval_valid_until` | build · backend-engineer · sec | P1 | E-013 | L | C-04, C-05 |
| C-32 | Kernel: `wait` step, `Descriptor.Waits`, sweeper exemption, deadline expiry | build · backend-engineer · sec | P1 | E-013 | L | C-31, C-06 |
| C-33 | Entra connection: certificate, permission families, verify EV1–EV5, no secret input | build · directory-engineer · sec | P1 | E-013 | L | C-09, C-12, X4 |
| C-34 | Entra connection: activate, write gate, HybridLink attributes, monitoring health | build · directory-engineer · sec | P1 | E-013 | M | C-33 |
| C-35 | Entra connection: certificate rotation without downtime | build · directory-engineer · sec | P2 | E-013 | M | C-34 |
| C-36 | Writable-group allow-list: store, step-up Action, Plan refusal | build · backend-engineer · sec | P1 | E-013 | M | C-33, C-09 |
| C-37 | Group classification, Conditional Access reads, weakening flag, breadth text | build · directory-engineer · sec | P1 | E-013 | M | C-34 |
| C-38 | Entra delta sync of users and groups with link/token binding and `cloud_seen_at` | build · directory-engineer · sec | P1 | E-013 | L | C-10, C-11, C-12 |
| C-39 | Sync licence SKUs and per-user assignments; scheduled reconcile | build · directory-engineer · sec | P1 | E-013 | M | C-38 |
| C-40 | Targeted re-sync by id or anchor with budget and write priority | build · directory-engineer · sec | P1 | E-013 | M | C-39 |
| C-41 | Entra membership writes: add/remove, throttle, replication window, ambiguous outcome | build · directory-engineer · sec | P1 | E-013 | L | C-12, C-13, X2 |
| C-42 | Entra direct licence and `usageLocation` writes (opt-in families) | build · directory-engineer · sec | P2 | E-013 | M | C-41 |
| C-43 | AD create read-back on the pinned DC and `ms-DS-ConsistencyGuid` verify read | build · directory-engineer · sec | P1 | E-013 | M | C-04, CO-2, X3 |
| C-44 | HybridRequest entity with write-once digest (D1–D6) and `awaiting_sync` event | build · backend-engineer · sec | P1 | E-013 | L | C-09, C-32, C-43 |
| C-45 | Hybrid Plan: coupled AD+cloud items and the FR-10 checks | build · backend-engineer · sec | P1 | E-013 | L | C-31, C-36, C-37, C-39, C-44 |
| C-46 | Hybrid preview: reversibility classes, AD-synced group routing, Lossy removals | build · backend-engineer · sec | P2 | E-013 | M | C-45 |
| C-47 | Authority: Plan-time rule for an absent Entra object, Apply re-check of initiator and approvers, licence-group rule | build · backend-engineer · sec | P1 | E-013 | L | C-45, C-15, X1 |
| C-48 | Continuation evaluator: anchor-only lookup, live preconditions, sticky and transient holds | build · backend-engineer · sec | P1 | E-013 | L | C-44, C-40, C-47 |
| C-49 | Unattended-continuation binding: bound elements, `replan_changed`, refuse/hold/deny | build · backend-engineer · sec | P1 | E-013 | M | C-48 |
| C-50 | Wait status, late banner, expiry, Cancel, Check now, How to sync now | build · backend-engineer | P1 | E-013 | M | C-48 |
| C-51 | Resume: supersede, carry-over, fresh row on a new approval, one live continuation | build · backend-engineer · sec | P1 | E-013 | M | C-49, C-50 |
| C-52 | Cloud step executor: retry, read-back verify, partial outcomes, idempotent re-run | build · backend-engineer · sec | P1 | E-013 | L | C-41, C-42, C-49 |
| C-53 | Undo of a hybrid request: cloud removals first, AD delete Lossy | build · backend-engineer · sec | P1 | E-013 | M | C-51, C-52 |
| C-54 | Licence and group Actions on existing users, up to 50 per operation | build · backend-engineer · sec | P2 | E-013 | M | C-41, C-42, C-47 |
| C-55 | Source-of-authority view and search-row badge | build · backend-engineer | P2 | E-013 | M | C-39, X1 |
| C-56 | Register the three Entra datasets with masking | build · directory-engineer · sec | P2 | E-013 | M | C-39, C-71, X1 |
| C-57 | Hybrid hardening suite: secret canary, error codes, 100k scale, URL-assembly fitness, wait-window cases | test · test-engineer · sec | P2 | E-013 | M | C-53, C-15 |
| C-58 | Define the 2c OpenAPI operations for connection, hybrid, licence, group and datasets | spec · api-engineer | P1 | E-013 | M | C-04, C-07, C-09 |
| C-59 | Serve connection, link, rotation, writable-group and picker endpoints | build · api-engineer · sec | P2 | E-013 | M | C-58, C-34, C-35, C-36 |
| C-60 | Serve hybrid request, Check now, Cancel, Resume, Undo, licence and group endpoints | build · api-engineer · sec | P1 | E-013 | L | C-58, C-08, C-50, C-51, C-53, C-54, C-56 |
| C-61 | Design the hybrid flows: connect wizard, create, preview, wait states, breadth wording, group picker | design · product-designer | P1 | E-013 | L | — |
| C-62 | Build the Entra connection screens: wizard, health, rotation, writable groups | build · frontend-engineer | P2 | E-013 | L | C-59, C-61 |
| C-63 | Build the hybrid create, preview, request status and SOA badge screens | build · frontend-engineer | P1 | E-013 | L | C-60, C-61, C-55 |
| C-64 | Install Entra Connect on the Windows lab against the sandbox tenant (tier H) | ops · devops-engineer | P1 | E-013 | M | A-0026, X4 |
| C-65 | Run the Graph probes: G3 extended, G11 extended, OQ-F3/F4/F8/F9 | test · directory-engineer | P2 | E-013 | M | A-0026 |
| C-66 | Prove the hybrid demo on tiers E and H | test · test-engineer | P1 | E-013 | L | C-52, C-53, C-55, C-63, C-64, C-65, A-0026 |
| C-67 | Reports: match count in the run's one statement, preview class, `CompileCount` deleted | build · reporting-engineer · sec | P1 | E-012 | L | C-16, C-17, C-18, C-21, X3 |
| C-68 | Reports: grouping, aggregates, totals, Top N, presence operators, zone buckets | build · reporting-engineer · sec | P1 | E-012 | L | C-67, C-19, C-20 |
| C-69 | Report definition store: versions, lifecycle Actions, clone | build · backend-engineer · sec | P1 | E-012 | L | C-18, C-21 |
| C-70 | `Resolve` for custom definitions: operators, typed values, GUID re-authorisation, validate-only | build · reporting-engineer · sec | P1 | E-012 | L | C-19, C-67 |
| C-71 | Dataset-registry Boot rule: refuse a dataset whose scope roots do not render | build · reporting-engineer · sec | P1 | E-012 | S | C-19 |
| C-72 | Report sharing, per-field permission, `column_not_permitted`, fail-closed schedule fire | build · backend-engineer · sec | P1 | E-012 | M | C-69, C-70 |
| C-73 | Preview runs: caps, supersede, rows-only fallback, preview and refusal audit | build · reporting-engineer · sec | P1 | E-012 | M | C-67, C-70 |
| C-74 | Fitness RP-B1 (OpenAPI free-text lint) and RP-B2 (every run kind through `Resolve`) | test · reporting-engineer · sec | P1 | E-012 | M | C-20, C-70 |
| C-75 | Sync-set Action: add a schema attribute, refuse secrets, "Not synced yet" | build · directory-engineer · sec | P2 | E-012 | M | C-25 |
| C-76 | Exact GUID and DN identifier-list intake | build · reporting-engineer · sec | P3 | E-012 | S | C-70 |
| C-77 | Build `inventory.ResolveIdentifiers` | build · directory-engineer · sec | P3 | E-012 | S | C-23 |
| C-78 | Caller-named permission on `inventory.Search` with SE3-style test | build · backend-engineer · sec | P2 | E-012 | S | C-22 |
| C-79 | Act on results: run-bound selection, drill-down, Plan hand-off | build · reporting-engineer · sec | P2 | E-012 | M | C-68, C-73, X2 |
| C-80 | Export and schedule builder reports: grouped digest, version pinning, chart data, encoding | build · reporting-engineer · sec | P2 | E-012 | M | C-68, C-72, X3 |
| C-81 | Builder side of the importer: accept proposal, attribute map, apply as private draft | build · reporting-engineer · sec | P2 | E-012 | M | C-69, C-70 |
| C-82 | My reports, Shared with me and `/` search findability | build · backend-engineer | P2 | E-012 | S | C-69, C-72, C-78 |
| C-83 | Register the `audit.events` dataset | build · backend-engineer · sec | P3 | E-012 | S | C-24 |
| C-84 | Non-interference property test (RP-B3) and side-channel matrix | test · test-engineer · sec | P1 | E-012 | M | C-68, C-72, C-73, C-74 |
| C-85 | Define the builder OpenAPI operations | spec · api-engineer | P1 | E-012 | S | C-18, C-19 |
| C-86 | Serve the builder endpoints | build · api-engineer · sec | P1 | E-012 | M | C-85, C-69, C-70, C-72, C-73 |
| C-87 | Components: condition-tree filter builder and column chooser | build · component-designer | P2 | E-012 | M | C-110 |
| C-88 | Components: bar and line chart with table toggle | build · component-designer | P2 | E-012 | M | C-110 |
| C-89 | Builder screen: source, fields, conditions, live preview | build · frontend-engineer | P1 | E-012 | L | C-86, C-87, C-110 |
| C-90 | Builder screens: groups and chart, act bar, save, share, schedule | build · frontend-engineer | P1 | E-012 | L | C-89, C-88, C-79, C-80, C-82 |
| C-91 | Prove the builder on the lab and scale tier | test · test-engineer | P1 | E-012 | M | C-68, C-73, C-75, C-84 |
| C-92 | Import jobs: project, quarantine, size gate, quotas, per-job store, audit | build · backend-engineer · sec | P1 | E-017 | L | C-27, C-28 |
| C-93 | File parsers (CSV, XLSX, HTML) under the hostile-file limits | build · backend-engineer · sec | P1 | E-017 | L | C-92 |
| C-94 | ADMP DB-dump adapter: allow-listed tables, deny list, nothing stored | build · directory-engineer · sec | P1 | E-017 | L | C-92, C-29 |
| C-95 | Classifier and fidelity rows: typed filters, macros, scripts as text, tier0 and never-imported | build · directory-engineer · sec | P1 | E-017 | L | C-93, C-94 |
| C-96 | Report crosswalk and scheduled-report importer | build · reporting-engineer · sec | P2 | E-017 | M | C-95, C-81 |
| C-97 | Proposal store and Apply Action with applier-holds-every-privilege and step-up | build · backend-engineer · sec | P1 | E-017 | L | C-92, C-95 |
| C-98 | Technician mapping and invite-only technicians | build · backend-engineer · sec | P1 | E-017 | M | C-97 |
| C-99 | Fidelity report view and CSV/PDF export | build · reporting-engineer · sec | P1 | E-017 | M | C-95 |
| C-100 | Define the migration OpenAPI operations | spec · api-engineer | P2 | E-017 | S | C-27 |
| C-101 | Serve the migration endpoints | build · api-engineer · sec | P1 | E-017 | M | C-100, C-97, C-98, C-99 |
| C-102 | Design the import flow, proposal review and fidelity report | design · product-designer | P2 | E-017 | M | C-03 |
| C-103 | Build the import, fidelity report and proposal review screens | build · frontend-engineer | P1 | E-017 | L | C-101, C-102 |
| C-104 | Hostile-file corpus, fuzz targets and cap tests | test · test-engineer · sec | P1 | E-017 | M | C-93, C-28 |
| C-105 | Import the lab ADMP 8043 configuration and classify every item | test · test-engineer | P1 | E-017 | L | C-96, C-98, C-99, C-104, C-30, A-0036 |
| C-106 | Admin guide: hybrid create and Entra connection | docs · docs-writer | P3 | E-013 | S | C-63 |
| C-107 | Admin guide: the report builder | docs · docs-writer | P3 | E-012 | S | C-90 |
| C-108 | Admin guide: importing an ADMP configuration | docs · docs-writer | P3 | E-017 | S | C-103 |
| C-110 | Design the builder: build flow, group table with chart, share sheet, Plan hand-off (FB-7) | design · product-designer | P1 | E-012 | L | — |
| C-109 | Verify the 2c demo: every AC, every control, with evidence | test · qa-verifier | P1 | all | M | C-66, C-91, C-105, C-63, C-90, C-103 |

## 6. Acceptance criteria

Spec, ADR, design and research rows use checkable statements (ticket-craft §2); build and test rows use Given/When/Then citing the spec AC and the evidence.
Every row also needs title, summary, owner, links to the spec path and `depends_on`, which the table and §1 supply; the director adds the spec path in each body.

### 6.1 Spec, ADR, design and research checks

| Key | Checkable statements |
|---|---|
| C-01, C-02 | A review file under `specs/reviews/` with numbered findings and a verdict; C-02 covers TM-TB18-T1…T12, the allow/deny lists, §6.3 and the ownership lock |
| C-03 | E2.11 states its 2c scope; §8 and AC-26–28 marked 2d; AC-12 cites E2.6 §11.2; status moves off draft only after C-01/C-02 verdicts |
| C-04 | One dated amendment holds the eight §14.1 items, rules D1–D6, `Descriptor.Waits`/`WaitCondition`/step kind `wait`, the H3-m1 rule (identity always copied; window and digest copied only on carry-over; a new approval writes a fresh row), and its fitness is named (C-05, C-06); security-architect confirmed |
| C-07, C-11 | The amendment or contract lists each route or kind and its conformance or A15 case; C-11 also holds the host pin, `tid` check and the touched set group-and-member |
| C-09, C-10, C-21 | Each entity, state and permission in E2.7 §14.3, e2-7a and FB-3d has a domain-model row with invariants; no entity is left implied |
| C-14, C-15 | Blueprint rows and `modules/m365.md` exist; C-15 lists each TM-F-HYBRID case with the AC it maps to and records confirmation of H3-m1 and A3-m3's four conditions (TM §6.6/§6.4 rows are CO-5) |
| C-16 | ADR-0012 restates the unchanged ADR-0010 rules, carries RP3–RP5, restates RP3 without `CompileCount`, and names RP12/RP13; director ratifies; ADR-0010 gets `superseded_by` |
| C-18, C-19, C-20 | reports.md holds every FB-3a item, R3-m1 presence operators, R3-m2 zone rule with bucket set "day, week, month, quarter, year", R3-m3 no custom labels, the refusal-event writer and the Boot rule; C-20 is a review report with RP-B1…B3 defined |
| C-22, C-23, C-24, C-25, C-26 | The amendment, note, ruling or spec exists; C-26 has an inline URL per claim and `[UNVERIFIED]` tags; C-25 states permissions, backfill and the freshness label |
| C-27 | Module page states the job state machine, quarantine, proposal store and the Operation use for apply; blueprint row added |
| C-29, C-30 | Findings doc with the 8043 table/column list, deny-list candidates, EULA finding, T21–T25 timings, fixtures under test paths; `[UNVERIFIED]` where not seen |
| C-58, C-85, C-100 | OpenAPI checked in; one `x-permission` per operation; no free-text query member (builder: one allow-listed intake); paging and idempotency defined |
| C-61, C-102, C-110 | Flows with empty, error, loading and wait/late/held states on activeDIQ tokens; C-61 settles OQ-F5 (PM default: template field, no inference) and lists missing components |

### 6.2 Build, test and lab ACs

**Lane H (E2.7, e2-7a)**
- **C-05** Given the amended `transitions` block, when O4's property test replays random Operation histories, then the new edges pass and every other fails. Evidence: O4 CI output (red until C-31).
- **C-06** Given coupled blocking, gate expiry, sweeper exemption, Resume supersede and carry-over refusal, when O8 runs, then each has a failing-then-passing test, and O5 fails a declared wait with no evaluator. H AC-53. Evidence: O8/O5 CI.
- **C-08** Given an operation-level route lacking an undo pair or `x-permission`, when A15 runs, then the build fails. Evidence: seeded bad route.
- **C-12** Given the harness, when F-tier tests run, then each F-tier H AC is writable against it with no real tenant; unverified behaviour is tagged. Evidence: self-test.
- **C-13** Given the Entra rows, when conformance runs on the fake provider, then a `tier0` user is never added or removed, a not-yet-visible target is retryable, an ambiguous outcome is signalled and a dynamic closure blocks (H AC-28). Evidence: CC-WRITE Entra cases.
- **C-17** Given RP12/RP13, when CI runs, then any `CompileCount` call or second count statement fails (seeded violation) and RP3–RP5 stay green. B AC-B15. Evidence: CI plus statement log.
- **C-28** Given a planted deny-listed table, a missing fuzz target or a script route, when CI runs, then each fails. M AC-05, 11, 14.
- **C-31** Given a coupled group, when any check blocks, then all items block; a failed predecessor sends its successor to `cancelled`; `partially_succeeded` carries one of five `cloud_reason` values. Evidence: `coupled_block_blocks_all`, O4/O8 green.
- **C-32** Given a `wait` step before its deadline, when the sweeper runs, then it is neither re-driven nor stalled; after the deadline it expires; `platform/operation` imports no module. H AC-53. Evidence: `waiting_gate_not_swept_before_deadline`, `gate_expires_at_deadline`, import-graph check.
- **C-33** [ADM-159, I360-003] Given a consented app, when Verify runs, then EV1–EV5 pass, the tenant ID is fixed, no secret input exists, a deny-list permission, role or unexpired secret refuses activation with no acknowledgement, and two tenants never cross. H AC-01–05. Evidence: `ev3_refuses_deny_list`, `ev5_warns_user_readupdate_breadth`, token-type log, checklist screenshot.
- **C-34** Given EV3 failing, when any Entra write is tried, then it is refused until a pass; link declare/confirm needs rights over both sides; no `AuditLog.Read.All` shows "change monitoring off". H AC-08, 09, 11.
- **C-35** H AC-10: rotation without downtime, 14-day pending thumbprint, unknown key flagged, old key deleted. Evidence: the five named tests.
- **C-36** Given a group off the list, when Plan runs, then it refuses `group_not_writable(not_allow_listed)` with no AD write; list changes need step-up and `tenant-owner`. H AC-50 (list). Evidence: `group_not_on_allowlist_refused`, `allowlist_change_needs_stepup`.
- **C-37** Given the Group-membership family, when verified, then the breadth text shows, a missing Conditional Access read disables it, CA-excluded groups are proposed for `tier0`, a CA-include removal previews as a weakening, and PIM, dynamic and licence flags are read live. H AC-27 (reads), 28, 50 (text), 51.
- **C-38** [I360-003] Given users and groups, when sync runs, then inventory holds the FR-36 properties, a delta applies only changes, a lost token forces a full resync, and a foreign page or `tid` is refused. e2-7a AC-42 (delta), AC-55.
- **C-39** Given a changed assignment, when delta runs, then it appears after the targeted re-sync or the daily reconcile. AC-42 (licences).
- **C-40** Given Check now, when pressed, then one object and its correlation refresh with no Entra write; account and tenant caps bind human re-syncs only; continuation reads are never starved. AC-42 (Check now), AC-56, `continuation_reads_not_starved_by_check_now`.
- **C-41** [ADM-164, M365-007] Given a group add, when the user is a member then `already_applied`; on 429 the step stays `applying` and waits `Retry-After`, with at most four writes in flight; the replication 400 retries for 2 minutes; an AD-synced group is never written. H AC-29, 30, 32, 33.
- **C-42** [ADM-161, M365-005] Given the opt-in families, when applied, then `usageLocation` is read back before `assignLicense`, `removeLicenses` is always sent, 0 units blocks and a drop to 4 does not fail. H AC-13, 15; the Action emits only `usageLocation` (AC-45).
- **C-43** Given a create, when it records its identity, then `objectGUID` is the pinned-DC read-back by DN with `uSNCreated` above the pre-add USN, and a stamped `ms-DS-ConsistencyGuid` holds `anchor_tampered`. H AC-19, AC-47 (`create_records_guid_from_pinned_readback`).
- **C-44** Given AD `succeeded`, when the digest is stored, then one transaction writes result, digest and `awaiting_sync.started`; an UPDATE is refused; the event recomputes the digest; the D6 cap holds. H AC-47. Evidence: `activation_digest_write_once`, `awaiting_sync_event_carries_digest_inputs`, `window_cap_asserted`, `plan_hash_commits_to_derivation`.
- **C-45** [ADM-027] Given each FR-10 check in turn, when previewing, then the request is `plan_failed` naming check, field and fix, no AD write occurs, and "continue without the cloud steps" re-plans AD-only. H AC-06, 09, 14, 15 (plan), 19 (refusal), 28. Evidence: parametrised zero-AD-change test.
- **C-46** Given the preview, when rendered, then the password is Irreversible, licensed-group removal and the AD-create undo are Lossy with effects named, and an AD-synced group appears as an AD step. H AC-12 (preview), 32, 34, 52 (Lossy).
- **C-47** [ADM-131] Given a technician or approver, when scope, role or account is lost while waiting, then the steps are denied; a licence-carrying group step also needs `m365.licence.assign` over the member (read live, unreadable counts as licensed, a gained licence holds `replan_changed`). H AC-24, 36, 52. Evidence: `licence_gained_during_wait_holds`, `licence_flag_unreadable_fails_closed`, `synced_licensed_group_needs_licence_permission`.
- **C-48** Given a pre-staged cloud object with the anchor, a foreign object, two matches, a `candidate`, or a PIM-nested group, when the poll reads, then no write occurs and the hold is sticky or transient as FR-35 says. H AC-17, 18, 20, 21, 26, 27, 48 (holds).
- **C-49** Given a changed SKU, group or classification at Apply, when the object matches, then the cloud half holds `replan_changed` with zero writes; an equal diff runs without a second approval; a digest mismatch refuses the token. H AC-22, 23 (`digest_mismatch_refuses_token`).
- **C-50** Given a waiting request, when opened, then status names step, last and next check, interval and `approval_valid_until`; "late" shows at 3 × interval; Check now is limited to one per 30 s; Cancel needs its permission. H AC-16, 25 (expiry), 35.
- **C-51** Given a waiting or ended request, when Resume is pressed, then the original ends `cloud_superseded` in the same transaction, only one live continuation exists, carry-over applies only after `cloud_step_failed`, and a new approval writes a fresh row copying identity only. H AC-48, 49. Evidence: `resume_with_new_approval_writes_fresh_row_copies_identity`, `one_live_continuation_per_request`, `no_double_cloud_write`.
- **C-52** Given a licensed-group add that succeeds and a second add refused, when the request ends, then it is `partially_succeeded`/`cloud_step_failed` with per-step state; a `licenseAssignmentStates` error ends `verify_failed`; a re-run writes nothing; a lapsed attestation holds. H AC-07, 31, 33, 46.
- **C-53** Given a `succeeded` request, when undone, then cloud removals run first and the AD delete is Lossy; a waiting request cancels the continuation first. H AC-34.
- **C-54** Given 50 users, when a cloud group or licence is added, then one preview and approval cover all and a 51st is refused naming the limit. H AC-38.
- **C-55** Given four users, when opened or listed, then the badge reads AD, Cloud, Candidate (reason and fix) or Broken, and no cloud-only create control exists. H AC-37, 54.
- **C-56** Given a runner scoped to `entra_tenant`, when reading the datasets, then AD-derived columns are masked, `onPremisesImmutableId` is not a column and only reachable rows return. e2-7a AC-43, 57.
- **C-57** Given a hybrid request, when the audit chain, logs and plans are searched, then no password, certificate or token appears; every FR-35 code renders; a 100k tenant never enumerates members; no URL is assembled outside the home packages. H AC-39, 40, 41, 44, 45 and the wait-window cases AC-17–21, 47–49 in one suite.
- **C-59, C-60** Given the OpenAPI, when contract tests run, then every operation answers as specified with one `x-permission` and no free text. Evidence: contract tests green.
- **C-62, C-63** Given the screens, when QA clicks every control, then each works; empty, error, loading, wait, late and held states are screenshotted; the hybrid create takes ≤ 3 interactions after the form. H AC-12 (timing), 16, 37, 44.
- **C-64** Given the sandbox and Windows lab, when a user is created in the synced OU, then it reaches Entra with `onPremisesImmutableId` equal to the base64 `objectGUID`. Evidence: lab runbook, Graph read. Blocked by A-0026.
- **C-65** Given the sandbox, when the probes run, then each of G3, G11 (CO-6 is the PIM question), OQ-F3, F4, F8 and F9 has a recorded result or a kept `[UNVERIFIED]` with the cause, and C-12 is updated. Blocked by A-0026.
- **C-66** Given tiers E and H, when the demo runs, then H AC-12, 13, 16, 17, 18, 33, 34, 37, 44 and AC-10 (E) pass with recorded Graph reads and screenshots. Blocked by A-0026.

**Lane R (E2.6 builder)**
- **C-67** [ADM-097] Given any run, when it executes, then its match count is a typed field from the single cursor statement and `CompileCount` no longer exists, library runs included. B AC-B15, B42; RP12 green.
- **C-68** [ADM-097, ADA-101] Given a 5,000-user technician and a 100,000-user admin, when the same grouped report runs, then groups, counts, totals and chart buckets derive only from in-scope masked rows; over 10,000 groups is refused with a reason; "has a value / is empty" works. B AC-B08, B09, B17, B18, B38. Evidence: `grouped_counts_equal_scope_oracle`, `side_channel_matrix`.
- **C-69** [ADM-097] Given a saved report, when edited or archived, then versions are immutable, `unarchive` is a forward Action, `restore` is only the inverse, and migrations carry `-- write-class config`. B AC-B11, B12, B14, B44.
- **C-70** [ADM-097] Given hostile values and operators a column does not register, when validated or run, then values stay data (numbered arguments), errors echo no value, an unreadable GUID gives the same code as a missing one. B AC-B02, B06, B07, B39, B43. Evidence: `builder_hostile_values`, `resolve_operator_per_column`.
- **C-71** Given a dataset whose root kinds are not rendered, when the registry boots, then it refuses it and the builder lists no Entra source. e2-7a AC-43, B AC-B30. Evidence: `dataset_registry_refuses_unrendered_root`.
- **C-72** [ADM-102] Given a report shared Run or Edit level, when a recipient lacks a field, then display columns are omitted with a count, conditions and sorts refuse, an Edit save is checked against the editor, and a schedule fire fails closed. B AC-B10, B13, B45. Evidence: `column_not_permitted_matrix`, `edit_save_checks_editor`.
- **C-73** Given 31 previews in a minute, a second running preview, or a 10 s timeout, when run, then caps refuse with a reason, the rows-only fallback counts against the rate, and each started preview is audited once, refusals once per account per minute. B AC-B16, B19, B35. Evidence: `superseded_preview_audited`, `preview_refusals_aggregated`.
- **C-74** Given a free-text member added to the OpenAPI, or a run kind bypassing `Resolve`, when CI runs, then RP-B1/RP-B2 fail. B AC-B02.
- **C-75** Given a schema attribute, when added to the sync set, then existing users read "Not synced yet", the condition message carries no count, and four secret attributes are refused. B AC-B04, B05, B43. Evidence: `sync_set_addition`, `secret_attribute_refused`.
- **C-76, C-77** [ADM-096] Given a pasted list of GUIDs or DNs (C-77 adds more kinds), when resolved, then matching is exact under the runner's scope and unresolved values are one bucket. B AC-B26.
- **C-78** Given `inventory.Search` with a caller-named permission, when a picker runs under `reports.run`, then results are trimmed by that scope. Evidence: SE3-style test.
- **C-79** [ADM-098] Given a succeeded run, when the actor acts on rows, then targets derive from the stored run, expired is 410, a changed scope is 409, grouped rows are not actionable. B AC-B21–23, B41.
- **C-80** [ADM-100, ADM-101] Given a grouped report, when exported or scheduled, then the digest covers group and total rows, a new schedule version shows the diff, titles are encoded. B AC-B20, B24, B25, B27.
- **C-81** Given an importer proposal, when validated and applied with step-up, then a private unscheduled `draft` lands with a review banner and nothing runs. B AC-B28, B29, B44.
- **C-82** Given own and shared reports, when searched, then findings are trimmed by permission. B AC-B32.
- **C-83** Given `audit.events`, when a scoped reader runs it, then only the restricted columns and visible events return. B AC-B31. (Ships only if C-24 lands in time; otherwise the next slice.)
- **C-84** Given worlds differing only outside the runner's scope, when each run kind and export executes with the timeout off, then output is identical; two failing fixtures fail the test. B AC-B40, B38, B39, B09.
- **C-86** Given the OpenAPI, when contract tests run, then every builder operation matches it with one `x-permission`. B AC-B02, B37.
- **C-87, C-88** Given each component, when rendered in Storybook, then default, empty, error, loading and keyboard states exist, the chart has a table toggle with labels, and no value is invented.
- **C-89** Given T21 and T22, when timed, then ≤ 14 and ≤ 7 interactions; sources, fields and states are shown. B AC-B01, B03, B33, B36.
- **C-90** Given T23–T25, when timed, then ≤ 6, ≤ 4 and ≤ 5 interactions; every control works. B AC-B20–22.
- **C-91** Given the scale seeds, when run, then B AC-B08, B09, B34 (a >1,500-member group), B42 and B04 (lab sync) pass with the budgets met.

**Lane M (E2.11)**
- **C-92** Given hostile or oversized input, when imported, then the job aborts at the named limit, leaves no proposal, quotas hold and the audit records actor, SHA-256, build and counts. M AC-03, 04, 24.
- **C-93** Given XXE, path-traversal, expansion and formula-bearing files, when parsed, then nothing outside the job directory is read, each aborts at its limit and output is escaped. M AC-01, 02, 04, 06.
- **C-94** [MIG-02] Given the lab dump, when an adapter runs, then the query log shows only allow-listed tables and columns and the upload is deleted at job end. M AC-14, 15.
- **C-95** [MIG-02, MIG-03] Given scripts, unknown macros, unbalanced and raw-SQL filters, `tenant-owner` and `tier0` scopes, when classified, then each is `manual` or `not supported`, valid filters become typed ASTs and no code path executes output. M AC-09, 11, 12, 13.
- **C-96** [MIG-05, MIG-06] Given custom reports and schedules, when imported, then they carry `exact`, `changed`, `manual` or `not supported` per E2.6 §11.2, schedules are disabled with owner `manageengine` and an external recipient is flagged. M AC-12, 22; B AC-B28.
- **C-97** [MIG-02] Given a proposal, when applied, then Plan refuses without every grant's privilege or step-up and names the gap; before apply nothing is active. M AC-07, 08, 09.
- **C-98** [MIG-16] Given a shared technician login, when roles import, then no role proposal exists until each use is mapped; technicians arrive only as invitations. M AC-10, 15.
- **C-99** [MIG-03] Given an import, when the report opens or exports, then every item appears once with its class, content is encoded and each export is audited. M AC-06, 24.
- **C-101, C-103** Given the OpenAPI and screens, when QA clicks every control, then each works; headers-only, unsupported-build and unreachable-source states are shown. M §10 cases.
- **C-104** Given the corpus, when CI runs, then each importer format has a fuzz target with zero crashes and the cap tests pass. M AC-01–05, 25.
- **C-105** Given the lab ADMP 8043 configuration, when imported, then every item is classified in the fidelity report, the `exact` plus `changed` share is recorded, and AC-07, 15, 22, 24 hold. Exit criterion 6. Blocked by A-0036.
- **C-106, C-107, C-108** Given the running product, when each documented procedure is followed, then it works as written, with screenshots from the product.
- **C-109** Given the three demo paths, when verified, then every AC listed in C-66, C-91 and C-105 has evidence and every control on each changed screen was clicked. Blocked by A-0026 and A-0036 through its dependencies.
