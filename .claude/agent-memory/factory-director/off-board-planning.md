---
name: off-board-planning
description: How to run factory work on a machine without the board (fresh clone, factory/state empty) — documents only, carry-over file, review rounds by hand
metadata:
  type: project
---

`factory/state/` is gitignored, so a fresh clone has an empty board and none of the server's
unmerged `factory/T-*` branches (2026-11-10: K:\activeDIQ was a fresh clone; none of those
branches were on GitHub).

**Why:** a second board would restart at T-0001 and can't be merged; code on stale main without
the lab can't pass QA. CEO chose "plan here, build later" (decisions-log 2026-11-10).

**How to apply:**
- Check `git reflog` + `factory status` first. If the clone is fresh and every ticket count is 0,
  say so before reporting progress, and use the latest digest + state-of-the-product instead.
- Work on a named branch, documents only. Frontmatter `ticket: off-board (<branch>)`.
- Anything that needs an id (bugs found, decision-prep, research, the CEO's own decision) goes in
  `knowledge/business/scoping/<m>-board-carryover.md`. File it on the board at merge, then delete it.
- Run the stages yourself as subagents: author → solution-architect + security-architect in
  parallel → a fresh author with both reviews + director rulings → re-review. Fresh agents per
  round: authors and reviewers each used ~200k+ tokens per round on ~600–900-line specs.
- Give authors the Type-2 rulings up front (who owns cross-spec pieces, accepted ADR = new ADR,
  not an amendment). It saves a round. [[adr-ratification-flow]]
