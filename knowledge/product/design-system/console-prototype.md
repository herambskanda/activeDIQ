---
title: "Console search and help-desk reset: Storybook prototype and design note"
date: 2026-10-29
updated: 2026-10-29
status: draft
owner: product-designer
ticket: T-0672
decisions: [D-0005, D-0012]
---

# Console search and help-desk reset: prototype

**What it is.** A clickable Storybook prototype on the Ledger tokens (`web/src/ds`) for roadmap E1.7 and M1 demo criterion 4. Every name, code and count in it is **sample data** from `web/src/prototype/fixtures.ts`; the prototype is not part of the console bundle (`vite build` starts at `index.html`; nothing in `src/app` imports it).

**Run it.** `cd web && npm run storybook` (port 6006), or `npm run build-storybook` for the static site in `web/storybook-static/`. Start at **Prototype / Console / End To End**.

## What is in it

| Story | Shows |
|---|---|
| End To End | Home, search, user page, reset sheet, result. Counter at the top counts interactions against the T01 budget |
| Home Reset Task | The "Reset password & unlock" tile: search where Enter opens the reset sheet directly |
| Search Results / Long Names / No Match / Loading / Error | Search over 12,000 sample users by name, sAMAccountName, UPN or e-mail; status chips on every result; 40+ character name; empty, skeleton and error with Retry |
| Object Locked / Long Name No Factor / Unicode | User page: lock banner with source, Overview / Groups / History tabs, deep link with Copy link |
| Reset Verify | The sheet: impact list, code field, two toggles, resend |
| Reset No Factor Fallback | No phone enrolled: manager approval request |
| Reset Permission Denied | Says why and who owns that OU |
| Reset Protected Account | Typed confirmation, second approver; no code shortcut |
| Reset Not Locked | The unlock toggle is absent, not unchecked |

Also reachable inside the stories: three wrong codes block and log the attempt; correct code shows the passphrase once, with Copy, Hide/Show and a phonetic read-out; Done returns to the page with an "unlocked" banner and a History row.

## Decisions (usability, ours)

1. **Code sent when the sheet opens.** `R` is the deliberate act, so there is no "Send code" step. This is what brings the stage from the user page to **3 interactions** (`R`, type code, Enter). Confirmed by the security-architect (T-0719, 2026-10-29) with conditions C1–C8 in [ENH-09 spec §4a](../specs/enh-09-otp-and-totp-enrolment.md): the send is a POST from the `R` key or click, never from loading the route; re-opening within 5 minutes sends nothing; closing the sheet does not refund the hourly quota. A "Send a new code" button remains.
2. **The passphrase is not shown before verification**; it appears once after confirmation, so a shoulder-surfer or a wrong caller never sees it first.
3. **Impact list instead of a confirm dialog.** The sheet states exactly what will change (new passphrase, change at next sign-in, unlock since 09:12), so there is no second modal.
4. **Locked accounts rank first in search** and carry the lock time in the result, which removes the ME console load and the lock-column hunt (§3 T01 pain points).
5. **Protected accounts never get the shortcut.** Typed account name plus second approver (P6). The prototype stops at "waiting for approval"; the approval flow itself is not designed here.
6. **Keyboard first:** `/` search, arrows, Enter, `R`, Esc. Every control is also clickable.

## Budgets

See `knowledge/product/specs/top-admin-tasks-benchmark.md` §2.1: all 20 tasks with the ME count and our budget. Measured in the prototype: T01 **6** keyboard route, **5** via the Home tile, **3** from the user page (budget 7 and 3); T03 **3** (budget 3).

## Not in the prototype (on purpose)

- Search covers users only. Groups, computers and an "all results" page are in the spec, not here, because a result you cannot open would be a dead control.
- No Disable/Move/Delete buttons on the user page: they would be dead. They are separate tickets.
- No real directory, OTP or password generation. The server owns all three; the prototype's passphrase generator and code are fixtures.
- Self-service (end-user) reset is a different surface; not covered.

## Checks run

Playwright click-through of every control (search open/close, arrows, result click, tiles, tabs, Copy link, toggles, resend, cancel, Copy password, Hide/Show, Done, Retry, Restart, protected, no-factor and denied paths) and axe on the main states: no violations. Evidence screenshots: `factory/demos/evidence/T-0672/`.
