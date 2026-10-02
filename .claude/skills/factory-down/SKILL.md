---
name: factory-down
description: CEO command — stop the dispatcher and board gracefully (running workers are asked to hand off) and confirm.
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*)
---

# /factory-down

1. Run `factory/bin/factory down`. Running workers are asked to hand off, which can take a
   moment.
2. Confirm with `factory/bin/factory status`. The dispatcher and board should be stopped.
3. Reply in one or two lines: "Factory stopped", the number of workers that handed off (their
   tickets resume on the next `/factory-up`), and anything still running, with its PID.
