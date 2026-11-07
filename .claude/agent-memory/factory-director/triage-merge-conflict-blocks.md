---
name: triage-merge-conflict-blocks
description: Triage of tickets blocked on "dispatcher merge conflicted" — check the primary checkout, then trial-merge against current main and run the migrations test
metadata:
  type: feedback
---

When a worker blocks because the dispatcher's merge failed, don't just unblock it. Check three things, in this order:
1. `git status` / `.git/MERGE_HEAD` in the primary checkout. A stuck merge usually clears on its own between the block and the triage.
2. `git merge-tree --write-tree --name-only main factory/T-…` gives the real conflicts against the main of *now*, which may have moved dozens of commits.
3. `go test ./migrations/ -run TestMigrationNumbersAreUniqueAndContiguous` on main. Parallel branches land the same migration number, and main goes red without anyone noticing.

**Why:** In T-1065 (2026-10-31), T-0949 and T-1033 both blocked on a stuck T-0953 merge. By triage time that merge had been concluded, but both branches had real conflicts with main, and main carried a duplicate 0061 (T-1066). This was the fourth such collision, so it got a systemic fix: T-1067, a gate on the merged tree.

**How to apply:** Unblock tickets whose conflicts are only text, and name the files in the note. If the ticket needs a main fix first, set depends_on and leave it blocked (see [[triage-blocked-on-another-ticket]]). Commit your own dirty memory files in the primary checkout so they can't break dispatcher merges.

**Gate refusals on P7 branch names (T-1420, 2026-11-03):** the "new" findings come from repo refs, not from the candidate. Don't unblock, because the next gate run refuses again. The auto-mode classifier refuses `git branch -m` on shared branches, so go straight to a CEO action with the copy-paste rename (A-0039), file the gate fix (T-1422), and check whether a done ticket's commit is stranded on the wrong-named branch.
