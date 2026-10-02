---
name: qa-verification
description: activeDIQ QA stage — verify each acceptance criterion on the running product with evidence, exploratory charter, click every control, trace every number to the API, smoke and a11y checks, file bugs, advance or reject. Use for every qa stage.
---

# QA verification

QA is where "the tests pass" meets "an admin can use this". PatchIQ shipped a dashboard of
fabricated SLA numbers and screens full of dead buttons
(`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §11 #1, NC7) — every one of them had
passed review. You are the person who clicks. Owner: `qa-verifier`. Tooling is **provisional until
ADR-0001**; lab commands are in `testing-playbook`.

Templates: `reference/charter-and-bug.md` (exploratory charter, evidence note, bug ticket body).

## 1. Prepare (≤ 5 min)

1. `factory/bin/factory ticket show <id>` — ACs, spec link, the owner's evidence note, review notes.
2. In the ticket worktree: start the lab and the product on real seeded data —
   `make lab-up TIER=small` then the dev stack (`make dev-up`, provisional). Use the `scale` tier
   when an AC mentions volume or performance.
3. Note the build (`git rev-parse --short HEAD`) — every piece of evidence refers to it.
4. Evidence folder: `factory/demos/evidence/<id>/`.

## 2. Verify each acceptance criterion

For each AC, in order:
1. Reproduce the Given/When/Then **against the running system** — through the UI for UI ACs,
   through the API (`curl` with a lab token) for API ACs, and check the directory itself for
   effects (`ldapsearch` over LDAPS against the lab, or the lab test helper). Re-running the
   owner's unit tests is not verification.
2. Capture the evidence the AC names: command + output excerpt, and/or screenshot
   `<ac#>-<state>.png` (Playwright, or the existing E2E run with screenshots).
3. Record **pass / fail** with one line of why. A partial pass is a fail.

## 3. UI checks — every changed screen

- [ ] **Click every control** on every changed screen: buttons, links, menus, row actions, tabs,
      sort headers, filters, pagination, shortcuts. Each does what its label says. A control that
      does nothing, or a "coming soon", is a fail.
- [ ] **States**: loading (throttle the network), empty (an OU with nothing in it), error (stop the
      Samba container mid-request: `docker stop` the lab DC), partial (one of two DCs down,
      some bulk items failing), very large (scale tier, long names, 3,000-member group).
- [ ] **Every number traced**: for each count, date or status on the screen, find it in the API
      response (network tab or `curl`) and, for directory facts, in the lab (`ldapsearch`).
      Mismatch, a number not from the API, or hardcoded data → fail (**no fake data**).
- [ ] **Keyboard**: everything reachable by Tab in a sensible order; focus visible; Enter/Space
      activate; Esc closes dialogs and drawers; no keyboard trap.
- [ ] **Responsive**: 1280 and 1920 widths (plus 1024 for self-service screens); nothing clipped
      or overlapping.
- [ ] **Dark mode** and light mode: legible, tokens only, no hardcoded colours.
- [ ] **Copy**: matches the spec; errors say what happened and what to do; AD terms correct.
- [ ] **Permissions**: as a lower role (lab RBAC fixture), controls the user may not use are hidden
      or disabled with a reason, and the API refuses them too.

## 4. Exploratory charter (10–20 minutes, time-boxed)

Write the charter before you start: *Explore `<area>` with `<data/tools>` to discover `<risk>`.*
Pick risks that this change could plausibly break. Proven sources of bugs in this product:

- hostile names (commas, `#`, quotes, leading spaces, Unicode) in every input and display;
- scope edges: an object just outside the delegated OU; a user in a nested group;
- double-submit, back button, refresh during a running job, two tabs editing the same user;
- DC unreachable or slow; certificate errors; token expiry mid-session;
- time: accounts expiring today, time-zone boundaries, "never" values;
- volume: 10k-row bulk input, 50k list scrolled to the end, export of a large report.

Log what you tried, what you saw, and every anomaly — in the evidence note, not in your head.

## 5. Regression smoke and accessibility (≤ 10 min)

- **Smoke** on the same build: sign in → list users → open a user → one write on the lab (e.g.
  reset a password) → its audit event appears → one report renders → jobs page. Any break → fail
  (and a P1 bug if it is outside this ticket's diff).
- **Accessibility quick check** on changed screens: automated scan (axe via Playwright, test-only
  dependency) with zero serious/critical findings; labels on inputs; headings in order; contrast
  in both themes; live region announces job progress and toasts. Full audits are
  `design-system`/`ux-review` work; this is the floor.

## 6. Bugs

- A failure **against this ticket's ACs or changed screens** → it goes in your reject note (§7);
  do not file a separate ticket.
- A defect **outside this ticket's scope** (pre-existing, or in an untouched screen) → file it,
  and do not reject for it unless it prevents verifying an AC:

```bash
factory/bin/factory ticket new --type bug --owner <owning engineer> --priority P2 \
  --epic <E> --milestone <M> --title "<what is wrong, where — imperative>" \
  --summary "<one paragraph: impact on the admin>" --body-file /tmp/bug.md \
  --ac "Given <repro state> When <action> Then <expected> Evidence: <test name or screenshot>" \
  --status backlog
factory/bin/factory ticket note <id> --by qa-verifier "Filed T-…: <one line>"
```

Body: repro steps from a clean lab, expected, actual, evidence paths, build, frequency, severity
(`reference/charter-and-bug.md`). P1 if it is on the milestone's critical path or loses data;
P0 if it is a security exposure or `main` is broken (tag `security-sensitive`; keep exploit detail
out of the title).

## 7. Decide

**Advance** only if: every AC passes with evidence; every control on changed screens works; every
number traces to the API; no serious/critical accessibility finding; smoke passes. Advance note =
the evidence summary (§ template), including what was **not** verifiable (e.g. Windows-only
behaviour pending the Windows lab) — never claim it.

**Reject** otherwise, with numbered must-fix items: AC or screen · what you did · expected ·
actual · evidence path. Taste opinions are notes, not rejects; send UX concerns to
`product-designer` as a follow-up ticket.

End with the `RESULT:` line (`factory-protocol` §5).
