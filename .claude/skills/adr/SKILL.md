---
name: adr
description: Write ADRs and move them up the ladder — numbering, fair alternatives, fitness functions, proposed → ratified (CEO for strategic forks, director + notice for technical) → accepted in CI, superseding. Use for any architectural decision.
---

# ADRs

An ADR exists so that in six months an agent who was not here can tell **what** we decided,
**why**, what we gave up, and **how CI stops us drifting**. PatchIQ had an "Accepted" ADR with zero
implementation (`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §11 #4) — so here an
ADR is `accepted` only when its fitness function runs in CI. Owner: `solution-architect`
(`security-architect` for security architecture). Conventions: `knowledge/README.md` (ADR ladder).

## 1. When to write one

Write an ADR when a choice is hard to reverse, shapes more than one module, or will be questioned
later: stack and deployment model (ADR-0001, pending), module boundaries and extension points,
data model and tenancy, read path (live directory vs synced store), sync mechanism, auth model,
credential storage, agent architecture on DCs, API versioning, a dependency that is
load-bearing. Not for: a library choice inside one module (ticket note), naming, a refactor.

## 2. Classify it first — who ratifies

| Kind | Examples | Ratified by | How |
| --- | --- | --- | --- |
| **Strategic fork** — changes what we sell, who can buy, what it costs to run | deployment model (on-prem / SaaS / MSP), platform strategy, "no runtime on DCs", cloud dependency | **the CEO** | `decision-prep` ticket → directional decision (`ceo-decisions`), framed in business terms; the ADR is the preview |
| **Technical** — everything else | language, sync mechanism, schema, API style, module seams | **factory-director** | `spec` ticket reviewed by the director, then a `notice` to the CEO |

When in doubt: if a customer, partner or the brand would notice the difference, it is strategic.

Routing: ADR `spec` tickets are owned by `solution-architect`, so the flow sends their review to
`factory-director` (owner = reviewer rule, `factory/README.md`) — that review **is** the
ratification. If another agent authors one (e.g. `security-architect`), `solution-architect`
reviews it and the ADR stays `proposed`; the advance note asks the director to ratify at triage.

## 3. Write it

1. **Number**: `ls knowledge/development/decisions/` — take the next free 4-digit number (ADR-0001
   is reserved for the stack/deployment decision). **Create the file immediately** to claim the
   number; if it is taken when you create it, take the next.
2. Copy `knowledge/development/decisions/0000-template.md` to `NNNN-short-title.md`
   (kebab-case, the decision not the topic: `0007-kerberos-first-ldap-binds.md`). Frontmatter
   `status: proposed`, `kind`, `ticket`.
3. **Context** cites sources: research in `knowledge/business/` and
   `knowledge/development/architecture/build-feasibility/`, specs, other ADRs, Microsoft Learn or
   RFC URLs. Unverified → `[UNVERIFIED]`. Ask `ad-expert` for directory semantics rather than guess.
4. **Alternatives — fairly.** At least two real alternatives, each in its best form, with what it
   would buy us. Test: would its strongest advocate sign your description? Include "do nothing /
   defer" when it is genuinely viable. Spikes in `garage/` are cited with their findings.
5. **Decision** is checkable: required, prohibited, and where exceptions are declared (e.g. "an
   exemption registry in `internal/platform/tenancy/exempt.go`, each entry with a reason").
6. **Consequences** name the negatives honestly, the follow-on tickets, and "revisit when".
7. **Fitness function**: the CI job that fails when the decision is violated — import rules, lint,
   a contract diff, a migration check, a benchmark, a grep. Write what it checks and where it will
   live; file the `chore`/`ops` ticket that builds it (owner the implementing engineer or
   `devops-engineer`, depends on this ADR's ticket). Mind the bypasses: a constructor-arity check
   is useless if code can avoid the constructor — pair it with what closes the bypass.
8. Strategic forks also get a one-paragraph business framing at the top of Context.

## 4. The ladder

| Rung | Status | Who moves it | What happens |
| --- | --- | --- | --- |
| Drafted | `proposed` | author | Not binding. Reviewed through the ticket flow. |
| Signed off | `ratified` | factory-director (technical) / CEO answer applied by director (strategic) | **Binding on design.** Set `ratified_on`, `ratified_by`, `decision`. Amend with a dated note at the top; reversal needs a superseding ADR. |
| Enforced | `accepted` | the ticket that lands the fitness function | Its CI job is green on `main`: set `accepted_on`, `fitness`. **Immutable** from here. |
| Replaced | `superseded` | the superseding ADR's ratification | Old ADR gets `superseded_by` and a one-line pointer; nothing else changes. |
| Dropped | `withdrawn` | factory-director | A proposal not adopted. Kept, with the reason — it records alternatives considered. |

**Technical ratification** (director, at review of the `spec` ticket): set the status fields, then
file the notice (one option, link the ADR, no `--blocks`):

```bash
factory/bin/factory decision new --kind notice --by factory-director \
  --title "ADR-0007 ratified: LDAP binds use Kerberos first" \
  --question "FYI: the factory ratified ADR-0007. Veto if it conflicts with your direction." \
  --context-file /tmp/adr-0007-notice.md \
  --option "a|Kerberos first, simple bind over TLS as fallback|knowledge/development/decisions/0007-kerberos-first-ldap-binds.md"
```

The notice context (≤ 150 words, plain language): the decision, why, what it costs, how to undo
it. Log it in `knowledge/memory/decisions-log.md` (`memory` skill). A veto arrives as feedback;
the director reverses it with a superseding ADR, never by editing.

**Strategic ratification**: the director files a directional decision via `ceo-decisions` with the
ADR as the option preview; when answered, director triage sets `ratified`, records `decision:
D-NNNN`, logs it, and unblocks the dependent tickets. The chosen option's text goes into Decision;
rejected options stay in Alternatives.

## 5. Immutability and superseding

- Never edit an `accepted` ADR except to set `superseded_by` or to apply an **erratum**. Never delete an ADR.
- **Erratum** (accepted ADRs): a correction of a factual statement that turned out false, such as a
  library's version or feature set or a measured number. It must change **no rule in Decision and
  no fitness check**. The author records it on the Amendments line as `E<n>`, with the date, the
  ticket, the evidence and the **original wording quoted verbatim**, then corrects the text in
  place. factory-director ratifies it and files a `notice`. A new binding constraint that needs
  enforcement gets its fitness ticket first. If the correction would change what the decision
  requires or forbids, it is not an erratum: supersede. First use: ADR-0001 E1 (T-0134).
- To change a decision: a new ADR that cites the old one in Context (what changed in the world),
  sets `supersedes:`, and climbs the ladder itself. The old one becomes `superseded` only when the
  new one is ratified.
- An ADR that loses its fitness function (job deleted or disabled) drops back to `ratified` and
  gets a P1 `chore` ticket — note it on the ADR's amendment line.

## 6. On the board

ADRs appear in the board's **Library** (it indexes `knowledge/`). Ratification notices appear on
**Decisions → Factory notices**; strategic forks appear under **Needs you**. Keep the architecture
map (`knowledge/development/architecture/`) linking every ratified ADR it depends on.

## 7. Review checklist (reviewer of an ADR ticket)

- [ ] Correct kind; a strategic fork is not being ratified by the factory.
- [ ] One decision; title states it; context sourced; non-obvious part named.
- [ ] ≥ 2 fair alternatives; negatives named; follow-ons filed or listed; revisit trigger.
- [ ] Fitness function concrete (job, location, what fails), with its bypass closed; ticket filed.
- [ ] Consistent with ratified ADRs, or explicitly supersedes one.
