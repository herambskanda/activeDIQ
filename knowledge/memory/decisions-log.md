---
title: Decisions log
updated: 2026-10-02
budget: 120 lines
---

# Decisions log

Newest first. `date · who · decision · why/source`. CEO decisions also live on the board as D-ids;
architecture decisions as ADRs in knowledge/development/decisions/. Roll entries older than the
current milestone into archive/ when this file nears its budget.

- 2026-10-02 · CEO · **Effort ceiling `high`; Sonnet-first; run cap 300/day.** The CEO was asked about the 60/day cap and chose 300/day. They capped Opus and Sonnet at high and asked for more Sonnet and fewer Opus. Factory calls inside that answer (notice, CEO may veto): Opus stays on 4 roles: director, solution-architect, security-architect and principal-engineer. Six roles move to Sonnet high: product-manager, project-manager, product-designer, ad-expert, market-analyst and service-manager. No xhigh or max even on escalation; the ladder is retry, then principal-engineer, then blocked. (factory/config.json models; OPERATING-MODEL §3)
- 2026-10-02 · factory · **Effort is enforced per launch.** The user-level `modelSettings` pinned Opus to xhigh, and that overrode agent frontmatter. As a result, Opus workers had run at xhigh since bootstrap, which breaks policy. From now on the dispatcher always passes `--effort`, taken from the agent frontmatter or an escalation override. The project `.claude/settings.json` pins Opus and Sonnet to high for subagents. (c0303f0; lessons.md)
- 2026-10-02 · factory · **M2 plan revision 2** (T-0031 review). Checkpoint 2a is demoed on `linux-oci`. The Windows adapters (sspi, gMSA, DPAPI-NG/TPM KEK, service host: T-0123–T-0126) close the profile gap before M2 exit. The first KEK adapter is the passphrase keystore. One scope-predicate producer: T-0089 defines the type, T-0094 produces it, search and reportsql consume it. The EP-10 and EP-15 hosts (T-0121, T-0122) come before their first features. Configuration writes wait for the T-0047 EP-3 ruling. (knowledge/business/scoping/m2-plan.md §2, decisions 7–12)
- 2026-10-02 · factory · **M2 planned** (T-0031): 14 M2 epics E-007…E-020 cover all 142 unconditional v1 rows; checkpoint 2a has 53 tickets (T-0064…T-0116). Foundations (primitives, connector, kernel) sit in M1/E-004 per roadmap E1.6; primitive order attr → dn → ldapfilter; search and reports share one scope evaluator from day one; 2a sign-in is local + TOTP, SSO at 2b. (knowledge/business/scoping/m2-plan.md)
- 2026-10-02 · CEO · **D-0005 Brand: a separate brand**, "Own palette and identity, independent of skenzeriq". Answered on the board with no note. It overrides the recommendation, which was a sub-brand on skenzeriq tokens. The factory's calls inside the answer went out as notice D-0008, which the CEO may veto:
  - Brand and UI style are picked together from three previews (T-0042, which replaces the cancelled T-0010).
  - No skenzeriq Electric Indigo or Geist.
  - skenzeriq appears only as publisher and legal entity.
  - Company documents stay on the skenzeriq brand; product artefacts use activeDIQ's.
  - The Factory Board stays on skenzeriq.
  - A name screen comes first (T-0044).
  ADR-0002 is amended: the design system is no longer shared. The design system is rebuilt in T-0043. (product-strategy.md §13 Q7; knowledge/development/decisions/0002-deployment-model.md)
- 2026-10-02 · factory · **ADR-0002 ratified** (strategic fork applying D-0002/D-0003; notice D-0007 lists the 8 calls made inside them, CEO may veto): `windows` (MSI) and `linux-oci` ship in v1, `saas` composed and CI-tested but not shipped; profiles are manifests, never conditionals; `tenant_id` + forced RLS from migration 1, one tenant per self-hosted install; directories only through the connector contract (embedded + remote transports), credentials only in the connector; Entra via the customer's own app registration, cert sealed under the tenant key; server never on a DC, delegated AD rights only, no Entra admin-role rights (ADM-168 role removal out of v1); server on WS2019+ or Linux, managed DCs WS2016–2025; standalone from UEM except the `skenzeriq.agent.v1` host contract. Enforced by `fitness-tenancy` (T-0036) and `fitness-profiles` (T-0038). (knowledge/development/decisions/0002-deployment-model.md)
- 2026-10-02 · factory · **ADR-0001 ratified** (technical; notice D-0006, CEO may veto): Go (cgo-free) for server and agents; Rust + windows-rs for the LSASS/LogonUI DLLs, C++ only via the rule-4 spike gate; PostgreSQL the only stateful service (pgx/sqlc, River pending legal Check); .NET 10/PowerShell 7.6 sidecars by declaration only; macOS/PAM logon components out of scope. Enforced by `fitness-stack` (T-0022). (knowledge/development/decisions/0001-technology-stack.md)
- 2026-10-02 · CEO · D-0004 Signature set of 5 beyond parity: ENH-01 task-first console, ENH-04 preview + undo, ENH-07 automatic updates, ENH-05 report builder, ENH-09 help-desk caller verification; plus switch enablers and Tier-0 proof. ENH-11 → ENH-22 → ENH-20 come next. (knowledge/business/strategy/enhancement-catalog.md §3)
- 2026-10-02 · CEO · D-0003 Platform: standalone now on UEM principles, house stack and skenzeriq design system; shared endpoint agent via module contracts; converge on a common core later. (product-strategy.md §11)
- 2026-10-02 · CEO · D-0002 Deployment: self-hosted first (Windows installer + Linux/Docker), SaaS-ready multi-tenant core from the first migration. (product-strategy.md §13 Q2)
- 2026-10-02 · CEO · D-0001 v1 replaces ADManager Plus first, with Graph-based Entra ID / M365 provisioning pulled into v1. ADSelfService/ADAudit parity follow in later milestones. (product-strategy.md §13 Q1)
- 2026-10-02 · factory · Parity matrix uses the research IDs (ADM/ADA/ADSS/RMP/M365/ERP/I360); there are no AD360-### IDs. Switch enablers without ME IDs are listed separately as must items. (knowledge/business/competitive-analysis/feature-parity-matrix.md)
- 2026-10-02 · factory · Repo-local git identity "activeDIQ Factory <factory@activediq.invalid>" for factory commits (no global identity was set). CEO may change it.
- 2026-10-02 · factory · Built-in `Explore` overridden by a project agent on Sonnet/high, because the built-in defaults to Haiku (policy forbids). (.claude/agents/Explore.md)
- 2026-10-02 · factory · Workers are headless `claude -p --agent <role>` sessions launched by a deterministic dispatcher; code tickets get their own git worktree; the dispatcher merges after QA. (factory/README.md)
- 2026-10-02 · factory · Factory Board is a local web app (127.0.0.1:4747) over file-based state; macOS notifications when the CEO is needed. (factory/OPERATING-MODEL.md §1)
- 2026-10-02 · factory · Knowledge base follows the UEM conventions (frontmatter, status ladder, sourcing, three-rung ADR ladder). (knowledge/README.md)
- 2026-10-02 · CEO · 300k-token context budget per working stretch with graceful handoffs. (kickoff brief)
- 2026-10-02 · CEO · Model policy: Opus medium/high (xhigh/max only for hard escalations); Sonnet high/xhigh; no Haiku. (kickoff brief)
- 2026-10-02 · CEO · Operating model: the CEO answers only directional questions; the factory decides the rest and demos each milestone. (kickoff brief)
