---
name: blueprint-review-link-graph
description: Architecture-blueprint review checks — import rules must be satisfiable by the stated package layout; catalogue claims must hold for every table; script AC traceability
metadata:
  type: feedback
---

On architecture blueprints, check that the import rules can actually hold with the package layout the doc draws. Don't just check that the rules are stated.

**Why:** On T-0004 (blueprint v0, 2026-10-02), the draft looked complete. It had 83 parity rows traced, matched the ADRs and carried an import DAG. But one `internal/compose` package imported every module, the connector root and webui, and every `cmd/<role>` called it. That made its own "binary hygiene" rule (`go list -deps ./cmd/edge` has no connector or store) impossible, and it put connector credential code into the DC agent binary. A first review round reject caught it.

**How to apply:**
- For each `cmd/<role>`, trace what it imports. One shared composition package means every binary links everything. Ask for per-role composition packages.
- When a table header claims "every component has X", check that every sub-table has the X column. On T-0004, §5.4 had no EP column, which failed the AC.
- Every interface home named in an extension-point table needs a catalogue row with an owner.
- Grep for contradictions between catalogue rows and open items. On T-0004, a row said agent modules "host sidecars" while §13 left that open.
- Check parity traceability with a short Python script over the CSV (`phase`/`importance` columns). Don't eyeball it.
- For satellite binaries (agent, remote connector, edge), check that every arrow into a shared layer is restricted. Unrestricted `agentmodules → directory/*` reaches `store` through `inventory`. Check that "used only by X" claims appear in the must-not-link table.
- Re-review (round 2 of T-0004 advanced in one pass): tick each must-fix against `git show <rework>`, re-run both AC scripts, grep the follow-up tickets for the renamed paths, and send leftover nits as notes to the ADR or chore that will enforce them.

Related: [[review-check-ceo-answers-vs-draft-time]], [[adr-ratification-flow]]
