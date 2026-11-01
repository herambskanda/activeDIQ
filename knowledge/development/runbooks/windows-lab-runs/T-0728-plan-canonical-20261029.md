---
title: T-0728 — planner canonical order vs WS2025
status: draft
---
# T-0728 run, 2026-10-29

Target: external Windows lab (VM 119, WS2025), LDAPS cert-verified. Command:
`go test -count=1 -tags 'lab windowslab' -run TestWindowsLabSDWriteInheritance -v ./internal/connector/ad/`
Log: `T-0728-plan-canonical-20261029.log.txt`. Result: PASS.

- `planInh` now plans with `Normalize`; the lab's BlockKeepInherited object needed no move (moves=0, all inherited ACEs are allows).
- New assertion: after the write the DC-stored DACL has no rule-1/2 violation (`Order().Outcome` empty) and `VerifyAfter` accepts.
- The DC still re-orders within the allow block (first diff at ACE 0, rules 3/4 / tie order): not rights-relevant.
- NOT exercised on the DC: an inherited *deny* turned explicit behind an explicit allow (the inversion itself). The lab parent only carries allows; the inversion is covered by corpus SD-W10/SD-W18 (+N variants) in unit tests only. Follow-up ticket filed.
