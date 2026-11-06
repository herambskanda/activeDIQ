---
name: triage-env-blockers
description: Triage of tickets blocked on host resources (disk, Docker, sandbox denials) — measure first, then unblock with guardrails
metadata:
  type: feedback
---

When a ticket is blocked on the host environment (ENOSPC, Docker/OrbStack down, Bash denied), measure the current state yourself before deciding: `df -h /System/Volumes/Data`, `docker info`, `docker volume ls`. Often a human has already fixed it between the block and the triage.

**Why:** On 2026-10-02 (T-0203), T-0049 and T-0050 blocked on a full disk. By triage time the disk had 34 GB free and Docker was back, so unblocking right away was correct, with no CEO action needed.

**How to apply:** In the unblock note, list which leftover resources belong to the worker so it never touches another ticket's volumes. Insist that unexplained failures from the outage window get root-caused, not blamed on the disk. Repeat the rules: no `dangerouslyDisableSandbox`, no shared-scratch sweeps, keep logs in the worktree. Systemic fix: [[T-0204 dispatcher disk preflight]].

**Orphaned processes / contended benchmarks (T-1285, 2026-11-02):** `kill` on another run's PIDs is classifier-denied even for the director, so never retry it. Read the orphan's `-timeout` and start time to get its expiry, then unblock with "wait (Monitor until-loop), then reap only containers whose labelled PID is dead, then flock". For latency ACs on the shared host, set a validity rule: a pass under load counts as conservative evidence; a miss above host-CPU load is inconclusive, so block for a quiet window (dispatcher pause) rather than file a bug.
