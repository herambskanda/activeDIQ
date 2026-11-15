---
title: "ADR-0014: Chart images are drawn in-process by one pure-Go renderer (own scene + x/image rasteriser); no browser, no JS runtime, no sidecar"
date: 2026-11-15
updated: 2026-11-15
status: ratified
ratified_on: 2026-11-15
ratified_by: factory-director
decision: D-0035
owner: heramb
author: solution-architect
kind: technical
ticket: T-2108
fitness: fitness-chartimg CI1–CI5 (to be built; follow-up tickets below)
---

# ADR-0014: Chart images are drawn in-process by one pure-Go renderer

**Status:** **ratified 2026-11-15** on the T-2108 review (notice D-0035). It becomes
`accepted` when `fitness-chartimg` (CI1–CI5) runs in `make ci` on both profiles.
**Kind:** technical (no change to price, packaging, deployment or platform strategy).
**Deciders:** solution-architect (author), factory-director (ratifier). **Ticket:** T-2108.
**Spec refs:** reports-eb5-grouping-charts Q3, §5, §6.3, §6.4, FR-GC-19, **AC-GC-13**.
**Builds on:** ADR-0001 (pure-Go static binary, no cgo), ADR-0002 (two profiles, same binary), ADR-0010
(exports are serialised from the stored run), blueprint §12, safe-primitives encoders.

## Context

Grouped reports carry one chart ([EB-5 §4.2](../../product/specs/reports-eb5-grouping-charts.md)). The
chart must appear as an image in the **PDF**, as a standalone **PNG**, and **inline in scheduled mail**,
from the run's stored result, on `windows` and `linux-oci` alike. Q3 and AC-GC-13 say a renderer that
works on one OS is a defect and that images from identical data must match within a tolerance the
architect sets.

Constraints already in force:

- **One binary, pure Go, no cgo** (ADR-0001, ADR-0002). A renderer that needs a native library, a
  second toolchain or a per-OS build breaks the "same binary on both profiles" rule.
- The PDF writer is hand-built, with no library and no font embedding
  (`knowledge/development/architecture/modules/reports.md`, encoder rows). Only raster images are
  cheap to add to it.
- The server runs as a service on Windows and in a container on Linux. Anything we spawn is a
  process with the server's rights, rendering text that comes from the directory (untrusted).
- Group labels are untrusted text (EB-5 §4.2 rule 6).
- Linux ships `amd64` **and** `arm64`; Windows ships `amd64` (ADR-0002).

## Decision

1. **One package, `platform/chartimg`, owns chart-image drawing.** Input: a typed chart spec plus the
   run's stored rows (already trimmed, capped at 1,000 groups). Output: a `Scene` (a list of rectangles,
   polylines, arcs and text runs), then `Scene → PNG` and `Scene → SVG`. PDF, PNG export and mail all
   call it; nothing else draws a chart.
2. **Rasteriser: `golang.org/x/image/vector` for fills and strokes, `golang.org/x/image/font/opentype`
   for glyph outlines**, both BSD-3-Clause, pure Go. PNG via the standard library `image/png`.
   Pixels are drawn by our code; we parse no SVG.
3. **Layout is integer.** Geometry, tick positions and text advances are computed in `fixed.Int26_6`
   (or `int64` units) from design-system tokens. No `float64` layout maths. The only floats are the
   `float32` path coordinates handed to the rasteriser, and every multiply-add there is written with an
   explicit `float32(...)` conversion so the compiler cannot fuse it on `arm64` (the Go spec permits
   fused operations unless an explicit conversion intervenes:
   [Go spec, Arithmetic operators](https://go.dev/ref/spec#Arithmetic_operators)).
4. **Fonts:** IBM Plex Sans 400/600 and Plex Mono 400 as **unmodified TTF files compiled in with
   `go:embed`** (SIL OFL 1.1, the same families the design system already ships as woff2 in
   `web/src/ds/fonts/`). Hinting is off (`font.HintingNone`) and DPI/size are constants, so glyph
   outlines do not depend on the OS. **No system fonts are ever read.** Glyphs the font lacks (CJK,
   some symbols) draw the font's notdef box; the data table beside every chart carries the real text.
   This is the same limitation the PDF encoder already states.
5. **The PDF embeds the chart as a Flate image XObject of the PNG pixels** (drawn at 2× the placed
   size), not as vector paths. That keeps the PDF writer font-free and makes the PDF's chart bytes
   identical to the PNG export's pixels.
6. **Mail embeds the PNG inline** (`Content-ID`) when the run has a chart; the spec's "otherwise an
   attachment" branch (§6.4) is removed, because the renderer is on both profiles.
7. **The SVG** is emitted from the same `Scene` for the HTML export. All text goes through the
   existing XML/HTML encoders; the raster path has no markup.
8. **Limits:** image ≤ 2,400 × 1,600 px, ≤ 4 MiB PNG, render under a context deadline (default 5 s),
   at most `GOMAXPROCS/2` concurrent renders. No network, no filesystem access in the package.
9. **Tolerance for AC-GC-13** (the number the spec asked the architect to set):
   - `windows/amd64` vs `linux/amd64`: **byte-identical pixels** (SHA-256 of the decoded RGBA).
     Same Go version, same code path, integer layout: there is no legitimate source of difference.
   - `linux/arm64` vs `linux/amd64`: **per-channel difference ≤ 2/255 on ≤ 0.1 % of pixels, and no
     pixel off by more than 16/255.** This allows only anti-aliasing coverage rounding. `[PROPOSED]`
     numbers: the first CI run calibrates them, and the ticket that builds CI1–CI5 may tighten them
     but may not loosen them without an amendment to this ADR.
   - The PNG *file* may differ across Go releases (`compress/flate` output); the fitness function
     therefore compares decoded pixels, and pins the Go version in the golden manifest.

## Options considered

| Option | Verdict | Why |
| --- | --- | --- |
| **A. Own scene + `x/image` rasteriser, in process (chosen)** | Chosen | Pure Go, one binary, no process to sandbox, deterministic by construction, BSD-3. Cost: we write ~6 chart types of drawing code. v1 needs bar, column, line and pie/donut only (EB-5 §4.1). |
| **B. Embedded or sidecar headless browser** (Chromium via [chromedp](https://github.com/chromedp/chromedp), or `chromium --headless`) | Rejected | Ships ~150 MB `[UNVERIFIED size]` of a second runtime we must patch on a CVE cadence; a sandboxed browser inside a Windows service or an unprivileged container needs `--no-sandbox` or extra capabilities; rendering depends on OS fonts, GPU/driver and hinting, so the two profiles would not match; it is a large new attack surface fed with directory-supplied text. Fails ADR-0001/0002's "pure-Go static binary, same on both". |
| **C. JS charting library** (Chart.js / ECharts) **server-side** | Rejected | Needs a JS runtime with a canvas. The pure-Go interpreter ([goja](https://github.com/dop251/goja)) has no canvas; `node-canvas` needs Cairo (LGPL, native) `[UNVERIFIED]`; Node as a sidecar is option B's problem with a different runtime. We would also maintain two chart implementations (browser and server) with different output. |
| **D. [tdewolff/canvas](https://github.com/tdewolff/canvas)** (MIT; PNG, PDF, SVG renderers, font handling) | Rejected for v1, revisit | Fits well, but it is a large surface (text shaping, bidi, LaTeX, GPU backends) for six chart types; its optional HarfBuzz and FriBidi paths have native (cgo) variants and FriBidi is LGPL (its README warns of it), so a `cgo`-free, LGPL-free build must be pinned and policed. Its rasteriser is described as assembly-optimised, which adds an architecture-dependent path to a determinism requirement we have not measured. Revisit if chart types outgrow option A. |
| **E. [resvg](https://github.com/linebender/resvg)** (SVG → PNG) as a sidecar executable | Rejected | A Rust binary (a second toolchain, per-OS builds and signing), MPL-2.0 `[UNVERIFIED: not re-read]`, and it renders system fonts unless told otherwise. Option A already produces SVG from the same scene if we ever need a cross-check. |
| **F. wkhtmltopdf / HTML-to-PDF tools** | Rejected | Embedded old WebKit, LGPL, project archived `[UNVERIFIED]`; same class of problems as B, and it bypasses the PDF encoder that owns the About block and the caps. |
| **G. Vector PDF charts (paths and embedded fonts in the PDF)** | Deferred | Crisper zoom, but needs font subsetting/embedding in the hand-built writer and OFL reserved-name care. PNG at 2× is adequate for v1; the `Scene` already supports a later `Scene → PDF content stream` encoder. |

## Licence register

Rows added in this change (register §3): `golang.org/x/image` (BSD-3-Clause, **Clear**); IBM Plex
TTF files (SIL OFL 1.1, **Clear**, shipped unmodified with the licence text in the image and the
installer); and the five considered-and-rejected projects above, so the next person does not
re-evaluate them. We ship `x/image` statically linked inside our own binary: BSD-3 requires only the
notice, which the existing third-party-notices bundle carries.

## Consequences

**Positive**
- One implementation, both profiles, both architectures; the cross-profile requirement becomes a test
  of our own code, not of someone else's OS.
- No new process, no new runtime to patch, no new trust boundary. A bug in label handling is a Go
  bug in the server's process, covered by the existing fuzz and fitness practice.
- PDF, PNG and mail show the same pixels; the PNG footer (About facts, §6.3) is drawn by the same code.

**Negative**
- We own chart drawing code and its visual polish. Mitigation: only the types in EB-5 §4.1, tokens from
  the design system, goldens reviewed by `product-designer`.
- No complex-script shaping (Arabic, Indic) and no CJK glyphs in chart images. The adjacent table is
  the faithful rendering. If customers need it, the answer is a font addition, not a browser.
- Go-version bumps can change `compress/flate` bytes and, rarely, rasteriser rounding: goldens are
  regenerated deliberately, in a reviewed change, with the Go version recorded.

## Fitness function: `fitness-chartimg` (in `make ci`)

| ID | Fails the build when | How |
| --- | --- | --- |
| CI1 | A chart image is produced anywhere but `platform/chartimg`, or the package imports `os/exec`, `net`, `os` file APIs, `syscall`, `unsafe`, `C`, `chromedp` or any browser/JS-engine module; or has a `_windows.go`/`_linux.go`/OS build tag; or reads system fonts | AST/import scan in `tools/fitness/chartimg`, same style as `fitness-profiles` |
| CI2 | The golden corpus (every chart type × states: empty, single group, all "(none)", 1,000 groups, long label, markup label, wide-glyph label) renders to different pixels than the committed goldens | Test runs on `linux/amd64`; the same test runs on a `windows/amd64` job and on `linux/arm64` (emulated is acceptable); each emits `sha256(RGBA)` per case |
| CI3 | **Cross-profile comparison** exceeds the tolerance in Decision 9: windows vs linux amd64 must be byte-equal on pixels; arm64 within the stated bounds | `tools/fitness/chartimg compare <dirA> <dirB>` over the per-case outputs the CI jobs upload; this is the AC-GC-13 evidence |
| CI4 | The rasteriser's assembly and generic paths disagree on the corpus, or the build does not pin the path | Run the corpus with and without the `purego`-style generic path `[UNVERIFIED which tag x/image/vector honours: the T-build ticket must confirm]` and compare |
| CI5 | A PDF export's embedded chart pixels, a PNG export and the mail inline image from the same run differ, or a scheduled mail for a run with a chart carries no inline image | Integration test over `platform/export` and the delivery encoder; plus the licence/F4 check that the Plex files' SHA-256 and OFL texts match the manifest |

Until CI1–CI5 are green on main, this ADR stays `ratified`, not `accepted`.

## Follow-ups (tickets created by this ADR)

- Fitness function `fitness-chartimg` CI1–CI5 incl. the Windows and arm64 jobs (devops-engineer).
- Build `platform/chartimg` and wire PDF, PNG export and mail inline image (reporting-engineer).
- Architecture map and blueprint: add `platform/chartimg` row; EB-5 spec §6.4 drops the attachment fallback (solution-architect + product-manager).
- Licence register rows (done in this change); Plex TTF files added to the third-party notices.

## Revisit when

- A customer needs CJK or complex-script labels in the image (add a font or move to option D).
- Charts beyond the EB-5 set are specified (more than ~10 types: reconsider D).
- CI3 finds a real cross-architecture drift we cannot remove with integer layout and explicit conversions.
