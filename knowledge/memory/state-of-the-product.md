---
title: State of the product
updated: 2026-10-07
budget: 120 lines
---

# State of the product — activeDIQ

Newest first. One dated line per material change; link the source.

- 2026-10-07 · **Job queue settled: our own `SKIP LOCKED` table in `platform/jobs`, River not adopted** (T-0209; ADR-0001 E3 and ADR-0002/0003/0005 amendments ratified, notice D-0017). The DB refuses cross-tenant enqueue; no pool leaves `store`. T-0084 re-cut and building; T-0153 (operation pipeline) follows it.

- 2026-10-02 · **Brand and UI direction chosen: A · Ledger** (D-0012). It is light and dense, with cobalt, IBM Plex and a labelled left rail. activeDIQ's own tokens (`web/src/ds/tokens.css`, `--diq-*`, light and dark, AA-tested), brand guidelines and the rebased design skills and agents landed with T-0043. Design and UI work now uses them. (factory/demos/evidence/T-0043/)

- 2026-10-02 · **Write pipeline and audit trail ratified** (ADR-0005, notice D-0015). Every change, configuration included, is previewed, gated, applied with a step token, verified and undoable. Our audit trail is a per-tenant hash chain with signed, anchored checkpoints and an offline verifier. It becomes `accepted` when fitness-operation and fitness-audit run in CI (T-0154). Next: T-0153 (platform/operation), ahead of the M2 checkpoint 2a config writes T-0093/0095/0096/0104; T-0155 (blueprint). (knowledge/development/decisions/0005-operation-pipeline-and-audit-trail.md)

- 2026-10-02 · **Public API contract ratified** (ADR-0004, notice D-0014). Every route is an operation in one OpenAPI document or a reviewed `policy.yaml` entry. Our own generator emits the strict server types and handlers. The console uses only the generated client. There is one unmetered `/api/v1` that only grows. It becomes `accepted` when `fitness-api` A1–A14 runs in CI (T-0148, T-0149). Next: T-0147 (generator + skeleton), then T-0086 (apihost). (knowledge/development/decisions/0004-public-api-contract-openapi-first.md)

- 2026-10-02 · **Module system ratified** (ADR-0003, notice D-0013). Features plug in only as modules through the Registrar. Every table has one owning package. CI checks what each binary may link. It becomes `accepted` when `fitness-modules` runs in CI (T-0141). Next: T-0144 migrates the scaffold's Registrar; T-0145 brings the blueprint and the domain-model owner lines in line with it. (knowledge/development/decisions/0003-module-system-extension-points-only-on-ramp.md)

- 2026-10-02 · **Domain model v0 passed director review** (T-0006, after 4 rounds). It defines 55 entities (DM-01…DM-85), each with invariants and a lifecycle, and maps all 123 v1 ManageEngine concepts. Directory references are keyed by GUID, and append-only records have derived states. Hybrid AD↔Entra authority goes through a `matched` correlation gate. Hybrid shortcuts need two Entra takeover-blocking settings plus a Global Administrator attestation every 90 days (notice D-0009). The doc stays `review` until a human reads it. Follow-ups: T-0050 (CI invariants), T-0051 (lab claims), T-0052 (gPLink codec). (knowledge/development/domain/domain-model.md)

- 2026-10-02 · **Architecture blueprint v0 passed director review** (T-0004). It fixes the repo layout: a per-role composition root (`cmd/<role>` + `internal/compose/<role>`), the extractable `internal/platform`, `internal/directory`, `internal/connector`, and modules that plug in only through extension points. Every P1 must-have feature traces to a component. The doc stays `review` until a human reads it end to end. The scaffold (T-0014) can start; the module, API and operation ADRs come next (T-0045..T-0047). (knowledge/development/architecture/blueprint.md)
- 2026-10-02 · **Brand: activeDIQ is a separate brand** (D-0005), independent of skenzeriq. The UI look is not chosen yet. Next comes three brand-and-UI previews and a CEO pick (T-0042), then the activeDIQ design system (T-0043). Until then, wireframes stay greyscale. (knowledge/business/strategy/product-strategy.md §13 Q7)
- 2026-10-02 · **Deployment model ratified** (ADR-0002): Windows installer + Linux/OCI in v1, SaaS composed in CI but not shipped; multi-tenant from migration 1; standalone from UEM with a shared agent-host contract. Stack and deployment ADRs are both ratified, so product code may start; first up are the tenancy foundation (T-0037) and the fitness checks T-0036/T-0038. (knowledge/development/decisions/0002-deployment-model.md)
- 2026-10-02 · **Stack ratified** (ADR-0001): Go server/agents, Rust in-process DLLs, PostgreSQL only. Product code still waits for ADR-0002 (T-0003). Main risk under test first: go-krb5 channel-binding spike T-0023. (knowledge/development/decisions/0001-technology-stack.md)
- 2026-10-02 · **Direction set by the CEO** (D-0001…D-0004): v1 = ADManager Plus replacement + Entra/M365 provisioning, self-hosted first and SaaS-ready, standalone from UEM, signature set of 5. Scope lock and roadmap in progress (knowledge/business/scoping/).
- 2026-10-02 · Strategy drafted: executive summary, product strategy (positioning, 6 USPs, pricing options), enhancement catalog (28 ranked), feature-parity matrix (578 ME features; 220 must). Migration playbook, partner questionnaire and pilot outline drafted. (knowledge/business/strategy/, competitive-analysis/, service/, partnerships/)
- 2026-10-02 · Factory running: board at http://127.0.0.1:4747; first M1 tickets in flight (ADR-0001 stack, safe primitives). (factory/)
- 2026-10-02 · **Stage: pre-implementation.** No product code exists. Product code starts only after the stack/deployment ADR is ratified. (CLAUDE.md)
- 2026-10-02 · Code factory set up: operating model, runtime (CLI, dispatcher, board), agents, skills, hooks. (factory/OPERATING-MODEL.md)
- 2026-10-02 · Research corpus drafted: ManageEngine ADManager Plus, ADAudit Plus, ADSelfService Plus, AD360 suite & commercials, customer voice & security record, market landscape, technical feasibility. (knowledge/business/market-research/, knowledge/business/competitive-analysis/, knowledge/development/architecture/build-feasibility/)
