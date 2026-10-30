---
title: "Runbook: security advisory intake poll"
date: 2026-10-27
updated: 2026-10-27
status: draft
owner: devops-engineer
ticket: T-0270
---

# Runbook: security advisory intake poll

Opens one embargoed `security-architect` ticket per new private GitHub security advisory, so the
3-business-day acknowledgement target (`SECURITY.md`) does not depend on the CEO forwarding email.
The disclosure process itself is `security-disclosure.md` (T-0260); this runbook only operates the poll.

## What it does

`factory security poll` (and the dispatcher, daily, when enabled) lists
`repos/<repo>/security-advisories?state=triage` through the `gh` CLI and, for each advisory with no
ticket yet, creates a P1 `bug` ticket: neutral title `Private security report GHSA-…`, tags
`security-sensitive,embargoed`, owner `security-architect`, body = the advisory link only. Dedupe
is on `meta.ghsa_id` across all ticket statuses, so a closed ticket is never re-opened as new.
Embargoed tickets are never merged (dispatcher hold).

## Enabling (needs the CEO action from T-0260)

1. The factory GitHub account has the repository **security manager** role (CEO action).
2. `gh auth login` as that account on the machine running the dispatcher (token stays in `gh`'s
   store; never in `factory/config.json` or the environment of CI logs).
3. Smoke test: `factory/bin/factory security poll` — must print a count, not an error.
4. Set `security_intake.enabled` to `true` in `factory/config.json` (repo and `interval_hours` are there too).

## Failing loudly

GitHub returns an **empty list**, not an error, for `state=triage` to a caller without access. So the
poll first reads the caller's role (`collaborators/<login>/permission`) and refuses unless it is
one of `admin`, `security_manager`, `security-manager`. [UNVERIFIED] the exact `role_name` GitHub
reports for the security-manager role: if the smoke test says the role is wrong although the account
has it, add the reported name to `ADVISORY_ROLES` in `factory/lib/advisories.mjs`.
Every failure (not logged in, 403/404, role, odd response, malformed advisory) exits 1 on the CLI;
in the dispatcher it becomes a `security advisory poll failed: …` event on the board and is retried hourly.
**An absence of that event is not proof the poll works — check `factory/bin/factory ticket list` after the first real report.**

## Proof the checks bite

`factory/test/advisories.test.mjs` (run by `node --test factory/test/*.test.mjs`): wrong roles and API
errors throw and create nothing; a good report creates exactly one detail-free ticket; a re-poll adds none.
