---
name: triage-env-blockers
description: Triage of tickets blocked on host resources (disk, Docker, sandbox denials) — measure first, then unblock with guardrails
metadata:
  type: feedback
---

When a ticket is blocked on the host environment (ENOSPC, Docker/OrbStack down, Bash denied), measure the current state yourself before deciding: `df -h /System/Volumes/Data`, `docker info`, `docker volume ls`. Often a human has already fixed it between the block and the triage.

**Why:** On 2026-10-02 (T-0203), T-0049 and T-0050 blocked on a full disk. By triage time the disk had 34 GB free and Docker was back, so unblocking right away was correct, with no CEO action needed.

**How to apply:** In the unblock note, list which leftover resources belong to the worker so it never touches another ticket's volumes. Insist that unexplained failures from the outage window get root-caused, not blamed on the disk. Repeat the rules: no `dangerouslyDisableSandbox`, no shared-scratch sweeps, keep logs in the worktree. Systemic fix: [[T-0204 dispatcher disk preflight]].
