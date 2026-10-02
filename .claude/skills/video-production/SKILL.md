---
name: video-production
description: Produce activeDIQ demo and feature videos — script mapped to milestone goals, storyboard, Playwright recording on seeded data, narration, ffmpeg edit, cards, captions, export presets in factory/demos/<M>/video/. Use for video tickets and demos.
argument-hint: "[milestone or clip]"
---

# Video production

Videos show the **real product on real seeded data** — never a mockup, never a faked screen.
Owner: `video-producer`. Video tickets are reviewed by `product-manager` (flow `video`); milestone
demos run under the `demo` skill, which calls this one for the recording.

**Style is a CEO call made once** (advisory decision with **two 15-second samples**, `a.mp4` /
`b.mp4`, cut from the same scene, in `factory/demos/previews/<D-id>/`). The answer goes to
`knowledge/memory/ceo-preferences.md`. Until then the default is **"precise, calm,
product-first"**: the product fills the frame; cuts and 200 ms fades only; no music; no stock
footage; no zoom except to make small UI legible (≤ 1.5×, held still); ink title cards in the
design-system type; narration says what the admin is doing and why it matters, never hype.

## 1. Formats

| Format | Length | Beats | Use |
| --- | --- | --- | --- |
| Feature clip | 60–120 s | 4–7 | One capability, one persona, one job |
| Milestone demo | 5–8 min | one scene per milestone goal | CEO acceptance (`demo` skill) |
| Style sample | 15 s | 2–3 | CEO style decision only |

## 2. Tools — check before starting

```bash
ffmpeg -version | head -1                                         # installed (Homebrew)
ffmpeg -hide_banner -filters | grep -wE 'loudnorm|xfade|overlay'  # present
ffmpeg -hide_banner -filters | grep -wE 'drawtext|subtitles'      # ABSENT on this machine (no freetype/libass)
npm --prefix tools/playwright ls @playwright/test                  # pinned (T-0011); set up: make playwright-install
say -v Samantha "check"                                           # draft narration
```

- No `drawtext`/`subtitles` → title cards are rendered as HTML and screenshotted (§5), and
  captions ship as a soft track + `.srt` (§6). Burn-in only if a devops ticket installs an
  ffmpeg with libass (then `subtitles` appears in the filter list).
- Playwright is pinned in `tools/playwright/` (runbook `knowledge/development/runbooks/playwright-tooling.md`).
  If `make playwright-test` fails, fix the setup per the runbook — do not install ad hoc.
- Fonts: Geist / Geist Mono are not installed locally; cards fall back to the `tokens.css`
  stack (Helvetica Neue / SF Mono) — fine for drafts. Vendoring Geist (SIL OFL) needs a licence
  register entry (`knowledge/business/licensing/`) and a devops ticket.

## 3. Layout — `factory/demos/<M>/video/`

```
script.md                 beats, narration, mapped to goals (script-template.md)
storyboard.md             6–8 frames for a clip; one per scene for a demo
record/<clip>.spec.ts     Playwright recording script, one per clip
narration/<clip>/<nn>.txt narration text per beat (committed)
cards/<clip>-<nn>.html    title cards (committed)
captions/<clip>.srt       captions (committed)
raw/                      takes, audio, card PNGs, intermediates   (gitignored)
clips/<clip>.mp4          finished feature clips                    (gitignored)
```

The milestone's final demo cut is `factory/demos/<M>/demo.mp4` (per the `demo` skill). Committed:
the text and scripts that reproduce the video. Never committed: media (`.gitignore` covers
`*.mp4`, `*.mov`, `raw/`).

## 4. Procedure

1. **Script** (`script-template.md`): every beat names the milestone goal or acceptance criterion
   it proves, the exact on-screen action, and the narration (≈ 150 words per minute). Read the
   spec's "what we do better" — the beat that proves it is the heart of the clip.
2. **Storyboard**: one frame per beat — a screenshot from the running product (not a sketch)
   plus the narration line. `product-manager` may review the storyboard before recording on long
   demos; it is cheaper than re-recording.
3. **Data**: load the demo seed (`lab/seed/demo`, owned by `test-engineer`; `testing-playbook`, `demo` skill §1.3). Same seed, same
   names, every take. Missing data → extend the seed via a ticket, never hand-edit the UI.
4. **Narration first**: render each beat's audio (§6), measure its duration with `ffprobe`; the
   recording paces each beat to its audio length. Audio leads, video follows.
5. **Record** with Playwright (`recording.md`): 1920×1080, frozen browser clock, injected cursor
   highlight, smooth mouse paths, typed input at human speed. One `.spec.ts` per clip;
   re-runnable end to end. A failing step means the product is broken — file a bug, never
   work around it on camera.
6. **Edit** with ffmpeg (`ffmpeg-recipes.md`): transcode, trim per beat, join with cards, mux
   narration, normalise loudness, add captions, export presets (§7).
7. **Check** (§8), then advance the ticket with the output paths and durations.

## 5. Title cards

HTML on `../design-system/tokens.css`, dark ink ground (`--sk-ink`), rendered at 1920×1080 by
Playwright `page.screenshot`. Contents: mono eyebrow (`--sk-text-micro`, uppercase, tracked,
e.g. `[ M1 · USER LIFECYCLE ]`), one heading in the sans at 600 weight, the `activeDIQ▮` mark with
the accent cursor block in a corner. Opening card ≤ 3 s; closing card ≤ 4 s. No other text on
cards. Template in `recording.md`.

## 6. Narration and captions

- **Drafts and internal reviews**: macOS `say -v Samantha -r 170` (`ffmpeg-recipes.md`). These
  voices are for internal use only.
- **Anything published** (partner demo, website, customer) needs a CEO-approved TTS service or
  a human voice — that is money and leaving the building (`ceo-decisions`, categories 5 and 6).
- Narration style: second person or plain description, present tense, terms exactly as on
  screen; numbers spoken as shown.
- Captions: every published video. Write `captions/<clip>.srt` from the narration text with
  the measured beat timings (≤ 42 characters per line, ≤ 2 lines, ≥ 1 s each). Mux as a soft
  track (`mov_text`) and ship the `.srt` beside the file.

## 7. Export presets

| Preset | Video | Audio | Use |
| --- | --- | --- | --- |
| `master` | 1920×1080, 30 fps, H.264 High, CRF 18, yuv420p | AAC 48 kHz 192 kb/s, −16 LUFS | Archive, re-edits |
| `web` | 1920×1080, 30 fps, CRF 23, `+faststart` | AAC 160 kb/s | Board, demos, docs |
| `preview` | 1280×720, 30 fps, CRF 28, `+faststart` | AAC 128 kb/s | Quick review, decision samples |

Commands in `ffmpeg-recipes.md`.

## 8. Before you advance

- [ ] Every beat maps to a goal or AC; the clip length is in range.
- [ ] Real product, real seed data; no fixture-driven or edited screens; no secrets, tokens or
      real domains visible (the seed uses `lab.activediq.test`).
- [ ] Cursor visible; nothing on screen moves faster than the narration explains it.
- [ ] Audio at −16 LUFS ±1; no clipping; captions in sync (spot-check start, middle, end).
- [ ] Style matches `ceo-preferences.md` (or the default above).
- [ ] Note on the ticket: output paths, durations, the seed version, the build/sha recorded.
