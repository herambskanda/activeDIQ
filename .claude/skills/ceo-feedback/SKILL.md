---
name: ceo-feedback
description: CEO command — record the CEO's feedback on a demo, ticket, doc or decision, inferring the target from context.
argument-hint: "<feedback text>"
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*)
---

# /ceo-feedback

Feedback: $ARGUMENTS

1. Infer the target from this conversation. Take the most recent, most specific subject:
   - a demo being presented or just shown → `demo:<M>`
   - a ticket under discussion → `ticket:<T-id>`
   - a document opened or quoted → `doc:<repo-relative path>`
   - a decision just shown → `decision:<D-id>`
   - none of these → `general`
2. Ask only if two specific targets are equally plausible. Ask one AskUserQuestion with those
   targets as the options.
3. Sentiment: `love`, `ok` or `change`, only if the words make it clear. Otherwise omit it.
4. `factory/bin/factory feedback new --target <target> --text "<their words, verbatim>" [--sentiment <s>]`
   Never paraphrase or soften the text. If it is empty, ask for it.
5. Confirm in one line, for example: "Recorded F-0012 on demo:M1 — the director triages it
   next."
