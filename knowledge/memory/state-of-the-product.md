---
title: State of the product
updated: 2026-10-02
budget: 120 lines
---

# State of the product — activeDIQ

Newest first. One dated line per material change; link the source.

- 2026-10-02 · **Stack ratified** (ADR-0001): Go server/agents, Rust in-process DLLs, PostgreSQL only. Product code still waits for ADR-0002 (T-0003). Main risk under test first: go-krb5 channel-binding spike T-0023. (knowledge/development/decisions/0001-technology-stack.md)
- 2026-10-02 · **Direction set by the CEO** (D-0001…D-0004): v1 = ADManager Plus replacement + Entra/M365 provisioning, self-hosted first and SaaS-ready, standalone from UEM, signature set of 5. Scope lock and roadmap in progress (knowledge/business/scoping/).
- 2026-10-02 · Strategy drafted: executive summary, product strategy (positioning, 6 USPs, pricing options), enhancement catalog (28 ranked), feature-parity matrix (578 ME features; 220 must). Migration playbook, partner questionnaire and pilot outline drafted. (knowledge/business/strategy/, competitive-analysis/, service/, partnerships/)
- 2026-10-02 · Factory running: board at http://127.0.0.1:4747; first M1 tickets in flight (ADR-0001 stack, safe primitives). (factory/)
- 2026-10-02 · **Stage: pre-implementation.** No product code exists. Product code starts only after the stack/deployment ADR is ratified. (CLAUDE.md)
- 2026-10-02 · Code factory set up: operating model, runtime (CLI, dispatcher, board), agents, skills, hooks. (factory/OPERATING-MODEL.md)
- 2026-10-02 · Research corpus drafted: ManageEngine ADManager Plus, ADAudit Plus, ADSelfService Plus, AD360 suite & commercials, customer voice & security record, market landscape, technical feasibility. (knowledge/business/market-research/, knowledge/business/competitive-analysis/, knowledge/development/architecture/build-feasibility/)
