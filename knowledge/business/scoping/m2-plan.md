---
title: M2 delivery plan — epics and checkpoint 2a tickets
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: project-manager
---

# M2 delivery plan: epics and checkpoint 2a tickets

This plan turns the v1 scope lock ([v1-scope-options.md](v1-scope-options.md)) and the M2 section
of [roadmap-skeleton.md](roadmap-skeleton.md) into Factory Board work (T-0031). Every M2 epic
exists on the board. Only the first demo point, **checkpoint 2a "Find and report"**, has tickets.
Checkpoints 2b, 2c, 2d and exit get tickets when grooming reaches them. Board state is the source
of truth; this file records the reasoning.

## 1. M2 epics on the board

| Roadmap | Board | Title | Parity refs (matrix IDs) | First checkpoint |
|---|---|---|---|---|
| E2.1 | E-007 | Console and search | ADM-001–004, 007 | 2a |
| E2.2 | E-008 | Directory objects | 24 rows (ADM-008…077) | 2b |
| E2.3 | E-009 | Bulk, CSV and templates | ADM-010–015, 017, 018, 034, 037; I360-004 | 2b |
| E2.4 | E-010 | Preview, undo, history and audit trail | ADM-005, 033, 034, 098, 137–139; ADA-112 | 2a (history) |
| E2.5 | E-011 | Delegation and help desk | ADM-125–136; I360-020; RMP-042; ERP-014 | 2a (scope evaluator) |
| E2.6 | E-012 | Reports | ADM-083–087, 089, 092, 093, 096–103 | 2a |
| E2.7 | E-013 | Hybrid via Graph | ADM-009, 027, 131, 159–162, 164, 169; M365-005, 007; I360-003 | 2c |
| E2.8 | E-014 | Workflow and approvals | ADM-116–121 | 2d |
| E2.9 | E-015 | Automation and JML | ADM-039–044, 047, 104–107, 114, 146–148; ADSS-091 | 2d |
| E2.10 | E-016 | Integrations and API | ADM-188–192, 198, 204, 205; RMP-043; I360-022 | 2a (API contract, SMTP) |
| E2.11 | E-017 | Migration kit (ADMP) | none: MIG-01–06, 10, 14, 16 are playbook IDs, listed in the epic goal | 2c |
| E2.12 | E-018 | Platform and updates | ADM-158, 206, 207, 209, 210, 212, 213; RMP-046; I360-002; ADSS-129, 131 | 2a (connection, sync) |
| E2.13 | E-019 | Tier-0 proof and console security | ADM-141–143, 145, 208; ADA-111, 116; ADSS-126, 127; ERP-017; M365-018; RMP-044 | 2a (local sign-in) |
| E2.14 | E-020 | Exchange helper (conditional, FD-04) | ADM-026, 070 | only if discovery finds Exchange |

**Coverage check.** The 142 unconditional v1 rows from the CSV all map to an epic. That is
`phase = P1`, the FD-02/FD-03 pulls and ADSS-091. The roadmap table left eight duplicate rows
without an epic. They are placed here:
- ADA-112, ADM-137–139 → E-010, as our audit trail.
- ADSS-127, ERP-017, M365-018, RMP-044 → E-019.
- ADSS-129, ADSS-131 → E-018.
- I360-022 → E-016.

ADM-144 (could, P4) is left out of E-019 (v1-scope §3.6). ADM-168 is out of v1 (ADR-0002 rule 9, D-0007).

**Carried into epic goals from T-0031 notes:**
- E-013: the Entra attestation expiry alert and the audit-log-gap staleness rule (DM-10.I7).
- E-008: domain-model Q10 for GPO links.
- E-011: DM-35 Entra roots and `include_correlated`.
- E-017: TM-D21, TM-TB18, TM-F-MIGRATE and TM-Q28.
- E-018: the PostgreSQL standby question, the ENH-07 release-train design and TM-F-HOST.

E-006 (docs and video style) was already on the board for M2 and is unchanged.

## 2. Checkpoint 2a: what it proves and how it is cut

**Demo (roadmap §M2).** The CEO sees four things:
- search finds any object across domains;
- the object's history;
- the most-used ADMP reports run;
- those reports exported and scheduled.

**Factory decisions made in this plan (decide-and-note):**
1. **Foundations sit in M1 / E-004**, as roadmap E1.6 lists them: safe primitives, the directory
   connector, jobs, the API host, the module host, keys, audit and authz. The 2a features sit in
   M2. Two ticket types were added beyond the director's brief:
   - one build ticket per primitive unit (solution-architect note);
   - kernel tickets that no existing ticket covered: keys, audit, authz, blob and notify.
2. **The primitive order follows what each unit consumes.** Attribute codecs come first, then DN
   (ObjectRef needs GUID and SID), then the LDAP filter (its values are GUIDs, SIDs and DNs).
   `Secret` was split from the codecs to keep each ticket inside one session. All primitives
   depend on T-0033 (static fitness) and T-0034 (corpus gate). T-0034 therefore moves to M1, so
   the corpus lands with the first primitive. psx, pslit and proc have tickets but are not on
   the 2a path (P2/P3).
3. **Contract first.** These specs come before any feature code:
   - connector read contract (T-0064);
   - inventory, sync and search-index design (T-0065), which settles domain-model Q7 with T-0026
     and Q9 erasure with T-0047;
   - find, reports and connection specs (T-0066–T-0068);
   - one OpenAPI contract for 2a (T-0069).
4. **Search and reports trim by the same rule.** The delegation module's scope evaluator ships at
   2a, with only the NC and OU kinds (T-0094). Search and reports are never built without
   trimming. Retrofitting it later is the PatchIQ failure (lessons).
5. **Console sign-in at 2a uses local break-glass accounts with mandatory TOTP** (T-0096). SSO is
   2b (E-019). Because every sign-in alerts tenant owners (threat-model §7.2), notify (T-0095)
   lands first.
6. **Only tickets whose dependencies are done are `ready`.** The dispatcher's grooming trigger
   counts raw `ready` (factory/lib/candidates.mjs). Waiting tickets marked `ready` would starve
   grooming. Every 2a ticket meets the Definition of Ready in content: owner, Given/When/Then with
   evidence, links, dependencies and parity. Grooming promotes each one as its dependencies close.

**Made ready now** (all dependencies done):
- new: T-0064, T-0067, T-0068;
- existing tickets on the 2a critical path: T-0022, T-0036, T-0045, T-0046, T-0047, T-0023,
  T-0026, T-0049, T-0029.

T-0018, T-0026, T-0029 and T-0049 were raised to P1 because 2a consumes them.

**Dependencies added to existing proof tickets,** so each proof waits for the code it proves:
- T-0053 → T-0082;
- T-0054 → T-0080;
- T-0055 → T-0087;
- T-0056 → T-0089, T-0096.

## 3. Critical path and parallel lanes

- **Primitive and connector lane (critical, 10 deep across M1 → M2):** T-0022 → T-0033 → T-0034
  → T-0070 → T-0072 → T-0073 → T-0082 → T-0083 → T-0092 → T-0116. This is longer than
  ticket-craft's ~4. The order is inherent (each unit consumes the previous one) and crosses two
  milestones, so it is accepted and watched.
- **Inventory lane:** T-0026 + T-0047 + T-0064 → T-0065 → T-0091 → T-0094 → T-0097 → T-0112.
- **Kernel lane** (backend-engineer, parallel to directory-engineer):
  - T-0036 → T-0037 → T-0084 / T-0087 / T-0090;
  - T-0045 → T-0085 → T-0089;
  - T-0046 → T-0086 → T-0096.
- **UI lane:** T-0042 (CEO brand pick) → T-0043 → T-0108 / T-0109 → T-0110 → T-0111–T-0115.

## 4. Risks and items for the director

| Risk | Likelihood × impact | Mitigation / owner |
|---|---|---|
| solution-architect is a bottleneck. They write T-0045, T-0046, T-0047, T-0040, T-0048 and T-0061, and review every spec ticket (T-0064–T-0069) | High × high | Dispatcher order is P1 by age. The director may run the ADRs before T-0040/T-0048 |
| The UI lane waits on the CEO's brand pick (T-0042). Screens cannot start before T-0043 | Medium × high | Backend and specs proceed. Greyscale designs (T-0105–T-0107) do not wait |
| **No Windows lab and no CEO decision on lab spend (v1-scope §8 Q5).** This affects M1 demo criterion 2 (WS2025 with CBT), T-0051, T-0023's Windows leg and the FEAS Phase-1 exit | High × high | **Director:** file decision-prep for Azure lab spend and counsel review (T-0027 covers signing only) |
| M1 demo criterion 2 (the walking skeleton through the real UI) needs M2-labelled tickets T-0097, T-0110 and T-0112 | Certain × medium | **Director:** accept a connector-level skeleton for M1 exit, or count those tickets toward M1 |
| T-0053–T-0059 sit under E-006 "Productization foundations" (docs and video style), which looks misfiled | — | **Director:** re-epic them (suggested: E-004 / E-019) |
| River's licence check is still open (licence register) | Low × medium | Before GA. T-0084 notes it. The fallback is a SKIP LOCKED table |
| Discovery has not come back (§8 Q1). The 2a report slice is chosen from research | Medium × low | T-0067 marks the choice `[DISCOVERY]` for re-weighting |

## 5. Checkpoint 2a tickets

Keys match the `Plan:` line in each ticket body. M1 = foundation (roadmap E1.6), M2 = 2a feature.

| Key | Ticket | Title | Type · owner | P | Epic · M | Depends on |
|---|---|---|---|---|---|---|
| S1 | T-0064 | Specify the connector read contract: Describe, search, read, change feed | spec · directory-engineer | P1 | E-004 · M1 | T-0004,T-0005,T-0006,T-0007 |
| S2 | T-0065 | Specify inventory tables, sync passes and the search index | spec · directory-engineer | P1 | E-007 · M2 | T-0064,T-0026,T-0047 |
| S3 | T-0066 | Write the find spec: universal search, AD Explorer, object page, history | spec · product-manager | P1 | E-007 · M2 | T-0006,T-0008,T-0009 |
| S4 | T-0067 | Write the 2a reports spec: library slice, run, scope, export, schedule | spec · product-manager | P1 | E-012 · M2 | T-0006,T-0019 |
| S5 | T-0068 | Write the AD forest connection spec: onboarding, rights check, sync health | spec · product-manager | P1 | E-018 · M2 | T-0006,T-0007 |
| S6 | T-0069 | Define the 2a OpenAPI operations: sign-in, connections, search, reports | spec · api-engineer | P1 | E-016 · M2 | T-0046,T-0066,T-0067,T-0068 |
| P3 | T-0070 | Build attribute codecs: GUID, SID, FILETIME, GeneralizedTime, flags | build · directory-engineer | P1 | E-004 · M1 | T-0033,T-0034 |
| P3S | T-0071 | Build the Secret type and the unicodePwd codec | build · directory-engineer | P1 | E-004 · M1 | T-0033,T-0034 |
| P2 | T-0072 | Build the DN parser and builder with ObjectRef and GUIDRef | build · directory-engineer | P1 | E-004 · M1 | T-0070,T-0033,T-0034 |
| P1 | T-0073 | Build the LDAP filter AST, renderer and admin-filter parser | build · directory-engineer | P1 | E-004 · M1 | T-0072,T-0070 |
| P5 | T-0074 | Complete the SQL primitive: LikePattern, capped lists, protocol guard | build · backend-engineer | P1 | E-004 · M1 | T-0037,T-0033,T-0034 |
| P5R | T-0075 | Build the report compiler and dataset registry (reportsql, EP-8) | build · reporting-engineer | P1 | E-004 · M1 | T-0074,T-0045 |
| P4P | T-0076 | Build the constant-argv process runner platform/proc | build · backend-engineer | P2 | E-004 · M2 | T-0033,T-0034 |
| P4L | T-0077 | Build the display-only PowerShell literal platform/pslit | build · backend-engineer | P3 | E-004 · M2 | T-0033,T-0034 |
| P4X | T-0078 | Build the psx typed PowerShell client and op manifest | build · backend-engineer | P3 | E-004 · M2 | T-0076 |
| P4H | T-0079 | Build the pshost sidecar: typed AddCommand/AddParameter host | build · windows-engineer | P3 | E-004 · M2 | T-0078 |
| C1 | T-0080 | Bind the AD provider with signing and CBT; keytab credential; Describe | build · directory-engineer | P1 | E-004 · M1 | T-0064,T-0023,T-0071,T-0072 |
| C2 | T-0081 | Serve the connector contract over the embedded transport with directory/client | build · directory-engineer | P1 | E-004 · M1 | T-0080,T-0038 |
| C3 | T-0082 | Implement ScopedSearch, Read and ReadPerDC with scope enforcement | build · directory-engineer | P1 | E-004 · M1 | T-0081,T-0073,T-0049 |
| C4 | T-0083 | Implement ChangeFeed: DirSync with object security, deletes, cookies | build · directory-engineer | P1 | E-004 · M1 | T-0082,T-0018 |
| K1 | T-0084 | Build platform/jobs: tenant-carrying jobs, leases and schedules | build · backend-engineer | P1 | E-004 · M1 | T-0037 |
| K3 | T-0085 | Build the module host: Registrar, capabilities, generated module lists | build · backend-engineer | P1 | E-004 · M1 | T-0045 |
| K2 | T-0086 | Build apihost: strict JSON, problem types, x-permission, UI mount | build · api-engineer | P1 | E-004 · M1 | T-0046,T-0085 |
| K4 | T-0087 | Build platform/keys: KEK adapter, tenant data keys, Seal and Unseal | build · backend-engineer | P1 | E-004 · M1 | T-0037,T-0071 |
| K5 | T-0088 | Build platform/audit: per-tenant hash chain, checkpoints, verifier | build · backend-engineer | P1 | E-004 · M1 | T-0047,T-0037,T-0087 |
| K6 | T-0089 | Build platform/authz: permissions, roles, scoped assignments (EP-6) | build · backend-engineer | P1 | E-004 · M1 | T-0045,T-0037,T-0085 |
| K7 | T-0090 | Build platform/blob with the fs adapter and tenant-prefixed keys | build · backend-engineer | P1 | E-004 · M1 | T-0037 |
| B1 | T-0091 | Create inventory tables and the inventory read API | build · directory-engineer | P1 | E-007 · M2 | T-0065,T-0050,T-0072,T-0070 |
| B2 | T-0092 | Sync each naming context into the inventory: full, incremental, resync | build · directory-engineer | P1 | E-018 · M2 | T-0091,T-0083,T-0084 |
| B3 | T-0093 | Create and verify AD connections with sync status (connections module) | build · directory-engineer | P1 | E-018 · M2 | T-0068,T-0069,T-0081,T-0053,T-0088 |
| B4 | T-0094 | Evaluate directory delegation scopes over inventory ancestry (EP-6) | build · backend-engineer | P1 | E-011 · M2 | T-0089,T-0091 |
| B9 | T-0095 | Build platform/notify: SMTP delivery through the single egress client | build · backend-engineer | P1 | E-016 · M2 | T-0084,T-0087 |
| B5 | T-0096 | Build console sign-in: first-run setup, local accounts with TOTP, sessions | build · backend-engineer | P1 | E-019 · M2 | T-0086,T-0087,T-0088,T-0095,T-0069 |
| B6 | T-0097 | Search the inventory across domains with RBAC trimming (search module) | build · backend-engineer | P1 | E-007 · M2 | T-0091,T-0094,T-0074,T-0069,T-0086 |
| B7 | T-0098 | Serve object read, explorer children and the history timeline | build · backend-engineer | P1 | E-010 · M2 | T-0091,T-0094,T-0069,T-0086 |
| B8 | T-0099 | Run canned reports with scope and filters (reports module) | build · reporting-engineer | P1 | E-012 · M2 | T-0075,T-0091,T-0094,T-0067,T-0069 |
| B10 | T-0100 | Ship the remaining 2a canned report definitions | build · reporting-engineer | P2 | E-012 · M2 | T-0099 |
| B11 | T-0101 | Build CSV and XLSX export encoders with formula neutralisation | build · reporting-engineer | P1 | E-012 · M2 | T-0029 |
| B12 | T-0102 | Build PDF and HTML report encoders | build · reporting-engineer | P2 | E-012 · M2 | T-0101 |
| B13 | T-0103 | Export report runs and store them as expiring artefacts | build · reporting-engineer | P1 | E-012 · M2 | T-0099,T-0101,T-0090 |
| B14 | T-0104 | Schedule reports and deliver them by e-mail | build · reporting-engineer | P1 | E-012 · M2 | T-0103,T-0095,T-0084 |
| D1 | T-0105 | Design the find flows: search, explorer, object page, history | design · product-designer | P1 | E-007 · M2 | T-0066,T-0009 |
| D2 | T-0106 | Design the report flows: library, run, results, export, schedule | design · product-designer | P1 | E-012 · M2 | T-0067,T-0009 |
| D3 | T-0107 | Design sign-in, first-run and connection onboarding flows | design · product-designer | P1 | E-018 · M2 | T-0068,T-0009 |
| UC1 | T-0108 | Build the data table and empty, error and loading states | build · component-designer | P1 | E-007 · M2 | T-0043,T-0105 |
| UC2 | T-0109 | Build the search field, command palette, tree and timeline components | build · component-designer | P1 | E-007 · M2 | T-0043,T-0105 |
| W1 | T-0110 | Build the console shell with first-run, sign-in and MFA screens | build · frontend-engineer | P1 | E-007 · M2 | T-0096,T-0107,T-0043,T-0009 |
| W2 | T-0111 | Build connection onboarding and sync health screens | build · frontend-engineer | P1 | E-018 · M2 | T-0110,T-0093,T-0092 |
| W3 | T-0112 | Build universal search and results screens | build · frontend-engineer | P1 | E-007 · M2 | T-0110,T-0097,T-0108,T-0109 |
| W4 | T-0113 | Build AD Explorer, the object page and the history timeline screens | build · frontend-engineer | P1 | E-007 · M2 | T-0110,T-0098,T-0108,T-0109 |
| W5 | T-0114 | Build report library, run, results and export screens | build · frontend-engineer | P1 | E-012 · M2 | T-0110,T-0103,T-0108 |
| W6 | T-0115 | Build report schedule screens | build · frontend-engineer | P1 | E-012 · M2 | T-0114,T-0104 |
| X1 | T-0116 | Prove checkpoint 2a on the lab: sync, search latency, report accuracy | test · test-engineer | P1 | E-007 · M2 | T-0092,T-0097,T-0100,T-0049 |
