# Code-reviewer memory

- Branches of dependent tickets often carry merged unreviewed deps (T-1196 etc. before main): review only `git diff <merge-commit>..HEAD`, not `main...HEAD`; fitness reds in dep files (e.g. sync/mapper.go json v1, engine O2, ajv missing) are not the ticket's.
- sync/inventory Postgres tests are slow: run `-run 'TestPlan|TestPatch'` with `-timeout 30m` in background (~2 min for T-1197); do not run whole ./internal/directory/... (inventory alone ~20 min).
- Mutation check recipe: `git worktree add --detach $SCRATCH/mut HEAD`, edit there, run the one test, `git worktree remove --force`. Never alter the branch.
- Permutation/idempotence tests: confirm the "must" assertions make "all equal" non-vacuous, and neuter the order-fixing SQL (T-1197 belowSQL) to prove the test can fail.
