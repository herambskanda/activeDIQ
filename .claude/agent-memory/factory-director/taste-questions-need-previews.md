---
name: taste-questions-need-previews
description: Brand/identity questions sent as option text get overridden by this CEO. Attach a preview, and apply a no-note override literally plus a notice instead of asking back
metadata:
  type: feedback
---

Any brand, identity or "how should it look" question needs a real preview, even when it looks
structural, like brand architecture (sub-brand vs separate).

**Why:** D-0005 (2026-10-02) asked "sub-brand on skenzeriq tokens vs separate brand" as option
text only. The CEO had taken all four earlier strategy recommendations, but overrode this one on
the board, with no note, three days before the default. A text-only taste question invites an
override that the factory then has to interpret.

**How to apply:**
- Before filing a taste or brand decision, check that every option has a preview link. If not,
  route it through a design or decision-prep ticket first. See [[review-check-ceo-answers-vs-draft-time]].
- When the CEO overrides with no note, apply the literal option text. Make the remaining
  interpretation calls yourself (scope of the brand, what stays on the company brand, sequencing),
  and send them as a single notice (D-0008 pattern). Do not ask back.
- "Has a preview" means each option's `preview` field is set (`--option "id|Label|summary|path"`),
  not only markdown links in the context. The board renders "Open preview" only from that field.
  T-0042 filed D-0011 with links in the context only (preview:null on all options). There is no
  `decision edit`, so the fix was to withdraw and refile (D-0012). Check `decision list --json` on
  every taste review.
- Validated: D-0012 (3 clickable previews, side-by-side index, measured trade-off such as rows per
  screen, and a recommendation) was answered with the recommended option in about 90 minutes, with
  no note. Reuse that shape.
- Bundle related taste choices (brand + UI style) into one preview-backed decision, so the CEO
  judges them together and answers once.
