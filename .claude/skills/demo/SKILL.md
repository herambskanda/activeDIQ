---
name: demo
description: Run a milestone demo end to end — script mapped to goals, real seeded data, recording, package in factory/demos/<M>/, CEO walkthrough, feedback, acceptance. Use when a milestone nears demo-ready, or /demo [milestone].
argument-hint: "[milestone]"
---

# Milestone demo

The demo is how the CEO judges a milestone. It must show the real product doing the milestone's
goals, on real data in a real system, with the limitations stated openly. Owners:
`factory-director` (lead), `qa-verifier` (walks the script first), `video-producer` (recording).

Milestone: `$0`, or the one in `demo-ready` status, or else the active one
(`factory/bin/factory milestone list`).

## 1. Prepare

1. `factory/bin/factory milestone show <M>`: read the goal. List the milestone's done tickets
   and their acceptance criteria.
2. Write `factory/demos/<M>/script.md` from `script-template.md` in this skill's directory.
   Use one scene per milestone goal. Each scene names the goal, the acceptance criteria it
   proves, the exact clicks, and the expected on-screen result. Keep it to 6–10 minutes.
3. **Seed data into the real system.** Use the demo seed script (owned by `test-engineer`) to
   load the lab directory: realistic OUs, users, groups and computers, created through the
   product or LDAP, never shown by the UI from fixtures. The product shows what the directory
   holds. If a scene needs data the seed lacks, extend the seed with a ticket, not the UI.
4. `qa-verifier` runs the script end to end against the demo environment and records
   pass/fail per scene. A failing scene is fixed or cut. It is never faked, and a cut is listed
   in known limitations.

## 2. Record

Follow the `video-production` skill: a Playwright-driven run of `script.md`, narration, edit,
and captions, in the video style the CEO chose (`ceo-preferences.md`). The raw takes go to
`factory/demos/<M>/raw/` (gitignored). The final cut is `factory/demos/<M>/demo.mp4`
(gitignored; the board serves it locally).

## 3. Package — `factory/demos/<M>/`

| File | Contents |
| --- | --- |
| `script.md` | The scenes, mapped to goals and acceptance criteria, with the QA pass/fail per scene |
| `demo.mp4` | The narrated walkthrough |
| `known-limitations.md` | Every gap, cut scene, workaround and lab-only shortcut, each with its follow-up ticket |
| `how-to-try.md` | The URL of the live environment, sign-in (the lab account *name* only; the password lives in the local secret store, never in the repo), three things to try, and how to reset the data |

## 4. Publish

```bash
factory/bin/factory milestone set <M> status=demo-ready \
  demo.script=factory/demos/<M>/script.md demo.video=factory/demos/<M>/demo.mp4 demo.url=<live URL>
```

If `milestone set` rejects the dotted `demo.*` keys, check `factory/bin/factory milestone --help`
for the field syntax. Commit the package files by path (the video stays local). The board shows
the demo, and the CEO gets a notification.

## 5. Present

When the CEO runs `/demo`, or is in session:

1. Give the milestone goal in one line. Then say what is in scope today and what is not, from
   `known-limitations.md`, before the first scene.
2. Walk the script scene by scene. Offer to drive the live environment in the browser. If not,
   play the video or point to it on the board. After each scene, pause for reactions.
3. Do not explain away a problem. Note it, and move on.

## 6. Capture feedback

Record every reaction as feedback on `demo:<M>`, using the board form or `/ceo-feedback`:

```bash
factory/bin/factory feedback new --target demo:<M> --sentiment change --text "<their words>"
```

Use the CEO's words verbatim. One item per point.

## 7. Close the loop

1. **Acceptance is the CEO's call** (category 7). Said live: record it with
   `milestone set <M> status=accepted|rejected` and add a line to `decisions-log.md`. Not
   present: file a directional decision "Accept <M>?" with the demo as the preview.
2. Triage each feedback item into tickets: `feedback triage F-… --note "…" --tickets T-…`.
   Record taste in `ceo-preferences.md` (`memory` skill).
3. Rejected: the "change" items become the next milestone's first tickets, and the demo is
   re-run when they are done. Accepted: update `state-of-the-product.md` and activate the next
   milestone.
