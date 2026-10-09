---
name: no-claude-artifacts-for-activediq
description: Never publish activeDIQ visuals/docs as claude.ai Artifacts; put them in the factory Library (knowledge/ + board) in the board's theme
metadata:
  type: feedback
---

Never publish anything for this project to the claude.ai Artifact site. Visuals and docs go in the
factory's Library (the board's Library tab, fed from `knowledge/`, `factory/reports`, `factory/demos`),
styled with the board's tokens (`factory/board/public/tokens.css`, `--sk-*`: monochrome + one indigo signal).

**Why:** CEO, 2026-10-09, after I published an architecture diagram as an Artifact: "never publish
artifacts on claude website for this project. i need it in factory's library." The project's contact
surface is the Factory Board; the repo is public, so docs belong beside the code.

**How to apply:** this overrides the Artifact tool's "publish when a page would be clearer" default.
Write markdown into `knowledge/…` (listed automatically) and, for interactive visuals, a
self-contained `.html` beside it linked from the markdown (served by the board at `/api/file`).
