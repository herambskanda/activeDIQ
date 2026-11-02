---
name: hand-landing-factory-fixes
description: Landing factory/ code by hand — scoped premerge argv that keeps exit codes, reuse cached baselines, and the dispatcher restart needs a human
metadata:
  type: feedback
---

When landing done factory/ tickets by hand (T-0975 precedent, T-1312 on 2026-11-02):
1. `make -k ci` reads nothing under factory/ (only secrets-scan scans the whole tree). Use a scoped dry run:
   `factory premerge T-… -- sh -c 'node --test factory/test/*.test.mjs; t=$?; make -s secrets-scan; s=$?; echo "node-exit=$t secrets-exit=$s"; exit $((t|s))'` — about 3 minutes, not 80.
   Never pipe node through `tail`: the pipe hides node's exit code, and the gate printed PASS over a failing test.
2. If a full-CI head log already exists, judge it with premerge.mjs's own extractFindings/newFindings against a cached `baseline-<sha>.json` whose main differs only in memory/docs commits. That avoids an 80-minute baseline run.
3. Commit a known conflict resolution on the ticket's branch (merge main in, then run the suite) before you dry-run it. Never resolve it in main.
4. A session may not kill the dispatcher. Auto-mode refuses that as workload interference, even when it is SIGKILL-for-adoption. Raise a CEO `action new` with copy-paste commands, and never suggest `factory down`, which stops the workers. T-1336 makes the reload automatic.

**Why:** On T-1312 the first run was killed by the 90-minute cap while it was still on the full-CI baseline. The second run landed all three tickets in about 25 minutes, but could not restart the dispatcher.

**How to apply:** Do steps 1–3 for any hand-merge of factory/ code. Once T-1336 is merged, check whether the restart action is still needed. Related: [[triage-merge-conflict-blocks]], [[ceo-action-handover]].
