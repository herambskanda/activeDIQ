---
title: "ADR-0000: Template"
date: 2026-10-02
updated: 2026-10-02
status: template          # ADRs: proposed | ratified | accepted | superseded | withdrawn
owner: heramb
# Fill in on a real ADR (delete the lines that do not apply yet):
# kind: technical | strategic-fork      # who ratifies — factory-director | the CEO
# ticket: T-0000                        # the spec / decision-prep ticket that produced it
# decision: D-0000                      # the CEO decision (strategic fork) or ratification notice
# ratified_on: YYYY-MM-DD
# ratified_by: factory-director | heramb
# accepted_on: YYYY-MM-DD
# fitness: <CI job name(s) that enforce it>
# supersedes: NNNN-short-title.md
# superseded_by: NNNN-short-title.md
---

# ADR-0000: <The decision, stated as the decision — "LDAP binds use Kerberos first">

**Status:** proposed | **ratified YYYY-MM-DD** by <factory-director | heramb (D-NNNN)> — binding on
design | **accepted YYYY-MM-DD** — fitness function `<job>` runs in CI | superseded by
[ADR-NNNN](./NNNN-short-title.md)
**Kind:** technical (factory-director ratifies, notice to the CEO) | strategic fork (the CEO decides)
**Deciders:** <agents / heramb> · **Ticket:** T-NNNN · **Parity / scope refs:** ADM-…, ADSS-… (if any)

> Amendments (ratified ADRs only; accepted ADRs are immutable): `YYYY-MM-DD — what changed and why`.

## Context

What forces are at play — the problem, constraints, customers, deadlines, the Tier-0 security
posture, on-prem distribution, the ManageEngine estates we migrate from. Cite the research, spec
or ADR that constrains this (inline paths and URLs; `[UNVERIFIED]` where unverified). State the
thing that makes the decision non-obvious — if it were obvious, it would not need an ADR.

**For a strategic fork:** one paragraph in business terms — who can buy, what it costs to run,
what it does to time-to-market — before any technical detail.

## Decision

"We will …" in the active voice. One decision per ADR. Include the rules that make it checkable
(what is required, what is prohibited, where the exceptions are declared).

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| … | … | … |

Each alternative is one we would execute well, described as its best advocate would describe it.
An ADR that strawmans what it rejected is worthless in six months when the trade-off resurfaces.

## Consequences

**Positive** — what this buys us.

**Negative** — what this costs us and what we can no longer do easily. Name the pain honestly;
this section is why the ADR is worth reading later.

**Follow-on work** — tickets this forces (IDs once filed), and decisions it leaves open.

**Revisit when** — the observable condition that would make us reopen this (with a superseding ADR).

## Fitness function

How CI detects, automatically, that this decision has been violated or has decayed: a test, a
lint or import rule, a contract check, a benchmark. Name the job and where it lives. The ADR is
`accepted` only once this runs in CI. If it genuinely cannot be checked automatically, say why
and name the manual check and who performs it (it then stays `ratified`).
