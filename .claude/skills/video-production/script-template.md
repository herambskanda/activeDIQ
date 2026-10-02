---
title: "Video script: <clip or demo name>"
date: YYYY-MM-DD
milestone: M…
format: feature-clip | milestone-demo | style-sample
target_length: 90 s
persona: <AD admin | help-desk technician | SOC analyst | compliance auditor | IT manager | end user>
seed: <demo seed name/version>
build: <sha or version recorded at take time>
style: <from ceo-preferences.md, or "default: precise, calm, product-first">
---

# <Clip name>

**Goal shown:** <milestone goal, verbatim from `factory/bin/factory milestone show <M>`>
**Proves:** <AC IDs / spec "what we do better" claim>
**One-line takeaway:** <what the viewer should remember>

## Beats

| # | Goal / AC | On screen (exact actions) | Narration (≈ 2.5 words/s) | Duration |
| --- | --- | --- | --- | --- |
| 0 | — | Title card: `[ M1 · <AREA> ]` / <heading> | — | 3 s |
| 1 | <goal> | Open **Users**, type `jane` in ⌘K, Enter | "Jane Doe is locked out. The help desk finds her from anywhere with one search." | 6 s |
| 2 | AC-03 | … | … | |
| n | — | Closing card: <heading> | — | 4 s |

Total: <sum> s (target ± 10 %).

## Storyboard

| # | Frame (screenshot path in `raw/storyboard/`) | Narration |
| --- | --- | --- |
| 1 | `01.png` | |

## Notes for recording

- Objects used from the seed: <names, OUs>
- State to reset before each take: <e.g. re-lock Jane Doe via seed script `--relock`>
- Known product limitations to avoid showing (and listed in `known-limitations.md` for demos):
