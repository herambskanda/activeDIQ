---
name: preview-building
description: How to build self-contained clickable brand/UI previews for the board (T-0042) — what worked, what bit us
metadata:
  type: feedback
---

Build previews from one shared app (data + render + events) plus per-direction tokens, layout CSS and shell; a node build script inlines CSS, base64 fonts and JS into each HTML.

**Why:** the board serves previews sandboxed (`sandbox allow-scripts`, opaque origin), so relative links to CSS/fonts/images break; three hand-written pages would drift and triple the bug surface.

**How to apply:**
- Make every state a hash deep link (`#/users/x?sheet=reset&code=typed`) and add a preview-only state strip; screenshot all states with Playwright from `tools/playwright/node_modules` (run `npm ci --prefix tools/playwright` first).
- Compute contrast from the token files in a script (`contrast.mjs`) and fail the build on any pair under 4.5:1 (text) / 3:1 (UI); include status-tint pairs and text on banners.
- Flex-column page shells squash children with `overflow` (tabs, top bar vanished): set `flex:none` on direct children. Never name a function `history` inside the app (shadows `window.history`).
- zsh does not word-split `$var` in `for w in $3`; generate repetitive CSS (font-face blocks) in python/node instead.
- Measure density claims (rows fully visible at 1440×900) instead of estimating them.
- Run a scripted end-to-end click flow on all directions before advancing; check that deep-link states don't depend on earlier clicks (add a Restart link).
