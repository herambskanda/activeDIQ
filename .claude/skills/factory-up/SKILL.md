---
name: factory-up
description: CEO command — start the Factory Board and dispatcher, confirm they are running, and print the board URL.
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*), Bash(git rev-parse:*)
---

# /factory-up

Repository check: !`git rev-parse --verify -q HEAD >/dev/null 2>&1 && echo "has commits" || echo "NO COMMITS"`

1. Run `factory/bin/factory up`.
2. Confirm with `factory/bin/factory status`. The dispatcher should show a fresh heartbeat and
   the board should be up.
3. Reply in at most three lines:
   - "Factory running · board http://127.0.0.1:4747", or the exact error. On an error, run
     `factory/bin/factory doctor` and give its first failing check.
   - What needs the CEO, as a count.
   - **If the check says NO COMMITS:** "The repo has no commits, so workers cannot use
     worktrees and code tickets run one at a time in this checkout. Want me to make the
     initial commit?" Commit only if the CEO says yes. Before you do, confirm that `.gitignore`
     covers `factory/state/` and `.env*`.
