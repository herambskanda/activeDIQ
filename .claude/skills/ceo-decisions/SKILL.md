---
name: ceo-decisions
description: Decide whether a question belongs to the CEO and, if it does, file a decision request that meets the quality bar — options, previews, recommendation, what it blocks. Use before asking heramb anything, or when work needs a directional call.
---

# CEO decisions

The CEO makes directional calls; the factory makes every other call. A question that reaches the
CEO and should not have is a defect. So is a directional call the factory made silently.

## 1. Is it a CEO question?

First read `knowledge/memory/ceo-preferences.md` and `decisions-log.md`. **If they answer it,
apply the answer and cite the line — never ask what is known.** Then classify:

| CEO (directional) — one of the seven | Factory (Type 2) — decide, log, continue |
| --- | --- |
| 1. Scope and ambition — modules, enhancements beyond parity, cuts | Ticket breakdown, sequencing, priority within a milestone |
| 2. Brand and taste — UI style, density, video, docs tone | Component internals, token usage, copy that follows an agreed tone |
| 3. Commercial — pricing tiers, packaging, partner terms, external dates | Internal estimates and plans |
| 4. Architecture forks **with business impact** — deployment model, platform strategy | Language, framework, library (licence register permitting), schema, API shape |
| 5. Money, accounts, legal — paid services, cloud spend, licences, contracts | Free tools already in the licence register |
| 6. Anything leaving the building — proposals, published docs and videos | Internal docs, ADRs, runbooks |
| 7. Milestone acceptance | Whether a ticket is done |

Calibration on this product:

- **UI density of directory tables** → taste → `advisory`, with clickable previews, default in 72 h.
- **Go vs .NET for the backend** → factory → an ADR by `solution-architect` (`adr` skill) plus a
  `notice`. It becomes directional only if it changes something the CEO sells — e.g. "agent must
  run on DCs without installing a runtime" — and then it is framed in those business terms.
- **Pricing tiers** → `directional`, always.
- **Self-hosted vs SaaS vs both** → `directional`, framed as who can buy and what it costs to run.
- **Which ManageEngine features are v1** → `directional` (scope); how to build them is not.

Unsure? It is Type 2 if it is cheap to reverse and no customer, partner or the brand would notice.

## 2. Kinds

| Kind | Use when | If unanswered |
| --- | --- | --- |
| `directional` | Only the CEO can make it. | Dependent tickets wait; nothing else does. |
| `advisory` | You have a sound default but taste matters. | Recommended option applies at `--default-in 72h`. |
| `notice` | A notable Type-2 call already made. | Stands unless vetoed. |

## 3. The quality bar — every request, no exceptions

- **One question**, answerable in under two minutes. Two questions → two decisions, or batch.
- **2–4 options**, mutually exclusive, each with a one-line summary saying what it buys and what
  it honestly costs. No straw men; every option is one you would execute well.
- **Previews whenever taste is involved** (§4). Prose descriptions of a look are not acceptable.
- **Recommendation + rationale** in one or two sentences, grounded in research or CEO preferences
  (cite the file). Put the recommended option first, as `a`.
- **What it blocks** — ticket IDs, and in words what stops moving.
- **Reversibility** — what it costs to change our mind in a month.
- **Advisory: the default and when it applies.**
- Context ≤ 150 words, plain language, no jargon the CEO would need to look up. Sources inline.

`examples.md` has one directional and one advisory request, fully worked.

## 4. Previews

Directory: `factory/demos/previews/<short-slug>/` (e.g. `ui-density`, `video-style`), one file per
option (`a.html`, `b.html`, …) plus `index.md` saying what each shows. Use a descriptive slug,
not the decision ID — the ID is assigned only when the decision is filed. Each option's `preview`
field in the decision points at its file.

- **UI** — one self-contained HTML file per option, real layout, real token values:
  `<link rel="stylesheet" href="/tokens.css">` (the board serves the design system's
  `tokens.css`; open previews through the board). Inline everything else — CSS, SVG icons — the
  board serves each file standalone, so relative asset links break. Show the same screen in
  every option; vary only what is being decided. Content is realistic sample directory data,
  labelled "Preview — sample data" in the corner (previews are not the product).
- **Docs** — the same page written in each candidate style, as `a.md`, `b.md`.
- **Video** — a storyboard (`a.md`: 6–8 frames, each a screenshot or sketch + narration line)
  or a 15-second clip `a.mp4` (`video-production` skill).

Once Playwright is installed in the repo (a devops ticket), also save a screenshot of each HTML preview as `a.png`, for viewing without the board.

## 5. File it

```bash
factory/bin/factory decision list --status pending          # budget: at most 3 open directional + advisory
factory/bin/factory decision new --kind advisory --by <role> \
  --title "Default density for directory tables" \
  --question "How dense should user, group and computer tables be by default?" \
  --context-file /tmp/D-ctx.md \
  --option "a|Comfortable, compact toggle|40 px rows; admins switch per table" \
  --option "b|Compact|32 px rows; more on screen, harder to scan" \
  --option "c|Comfortable only|40 px rows; simplest, no toggle" \
  --recommend a --rationale "…" --default a --default-in 72h --blocks T-0031,T-0032
```

- The context file holds: context, per-option pros/cons, preview links, what is blocked,
  reversibility. `--multi` only when options genuinely combine.
- Directional: omit `--default`/`--default-in`. Notice: one option (what was decided), link the
  ADR, no `--blocks`.
- Confirm the printed ID matches the preview folder. If not (another session filed in between),
  `decision withdraw` it, rename the folder to the next free ID, fix the links, and file again.
- **Budget full** (the CLI refuses a 4th)? Never `--force`. Batch: fold related questions into
  one, or file a `decision-prep` ticket for `factory-director` with your draft in the body and
  block on it. The director decides what goes in front of the CEO.

## 6. While you wait

- New tickets that depend on the answer: `ticket new … --decisions D-…` (they cannot be claimed
  until it is answered). Your current ticket, if it cannot proceed:
  `factory/bin/factory ticket block <id> --by <role> --note "waiting on D-…: <question>"`.
- Everything else continues. Do the parts that hold under every option first.
- Never re-ask or chase. The board and the macOS notification are the reminder.

## 7. How answers are applied (factory-director triage)

The dispatcher launches director triage when a decision is `answered` or `defaulted` and not
applied. The director:

1. Reads the answer and the note. The note outranks the option label. If it is ambiguous, file
   one narrower follow-up — never guess.
2. Records it (`memory` skill): one line in `decisions-log.md`; generalisable taste or priority →
   `ceo-preferences.md` so the same question is never asked again.
3. Propagates: unblocks waiting tickets, creates or edits tickets for the chosen path, cancels
   ones that only served rejected options, updates the spec or ADR.
4. `factory/bin/factory decision applied D-… --by factory-director`.
5. A veto on a notice arrives as feedback: reverse the decision with a ticket, log it, record the
   preference.
