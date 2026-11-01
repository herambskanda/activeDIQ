---
title: M1 demo script — Foundation & direction
date: 2026-10-29
updated: 2026-10-29
status: draft
owner: factory-director
---

# M1 demo — Foundation & direction

This script is incomplete: the director adds the other scenes when the milestone nears demo-ready. Scene 4 below is the design-prototype scene (roadmap demo criterion 4, ticket T-0672).

## Scene 4 — A clickable design prototype with interaction budgets
- **Proves:** T-0672: "the stories for search, object view and the help-desk reset flow are clickable end to end"; the reset + unlock stage from the user page stays within 3 interactions.
- **Run:** `cd web && npm run storybook`, open **Prototype / Console / End To End**. Design note: [`knowledge/product/design-system/console-prototype.md`](../../../knowledge/product/design-system/console-prototype.md). Budgets for all 20 tasks: [`top-admin-tasks-benchmark.md` §2.1](../../../knowledge/product/specs/top-admin-tasks-benchmark.md).
- **Steps:** 1. Press `/`, type `priya r`, Enter. 2. Press `R`. 3. Type `482916` (the sample code shown in the sheet), Enter. 4. Read the counter at the top: 6 of 7, 3 of 3 from the user page. 5. Open **Reset Protected Account**, **Reset Permission Denied** and **Reset No Factor Fallback** to see the safeguards.
- **Expected on screen:** the new passphrase with a phonetic read-out, an "unlocked" banner, and a History row.
- **Narration:** Everything is sample data. The point is how few steps a help-desk call takes, and what the tool refuses to do.
- **CEO decision:** accept the look and flow, or redirect (criterion 4).
- **QA:** pending.
