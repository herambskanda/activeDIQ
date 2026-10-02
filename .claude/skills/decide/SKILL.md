---
name: decide
description: CEO command — walk the CEO through pending decisions (all, or one D-id) with multiple-choice questions, record the answers, summarise.
argument-hint: "[D-id]"
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*)
---

# /decide

Pending:

!`factory/bin/factory decision list --status pending 2>&1`

1. Scope: only `$0` if it was given, otherwise every pending `directional` and `advisory`
   decision, oldest first. For each, run `factory/bin/factory decision show <id> --json` and
   read the context.
2. Ask with **AskUserQuestion**, at most 4 questions per call. Batch any extras into a second
   call.
   - `header`: a short topic of 12 characters or fewer. `question`: the decision's question,
     followed by one sentence of context and what it blocks. Advisory decisions also get
     "Default: <option> on <date>".
   - Options: the **recommended option first**, with " (Recommended)" appended to its label.
     The others follow in their original order. `description` is the option summary.
   - `preview`, when the option has one, is a compact text rendering: the key differences in
     a few lines, plus the board link
     `http://127.0.0.1:4747/api/file?path=<preview path>`.
   - `multiSelect: true` only for decisions filed with `--multi`.
3. Record each answer with the CEO's words as the note:
   `factory/bin/factory decision answer <id> --option <id>[,<id>] --note "<their words>" --via cli`
   - If they chose "Other" and their text clearly picks an option with a tweak, record that
     option, with the text as the note.
   - If their text rejects every option, do not answer. Run
     `factory/bin/factory feedback new --target decision:<id> --sentiment change --text "<their words>"`
     so triage can reframe it.
4. Notices are not questions. List them on one line, saying they stand unless vetoed. If
   `factory/bin/factory decision --help` offers ack or veto verbs, offer them. If not, point
   to the board's Decisions tab.
5. Summarise in **three lines or fewer**: what was decided, what it unblocks (triage applies
   it on the next dispatcher tick), and what is still pending.

If nothing is pending, say "Nothing needs a decision" and stop.
