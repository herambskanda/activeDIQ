---
title: "Standard: secret scanning"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0013
---

# Standard: secret scanning

**Rule (CLAUDE.md #10): never commit secrets.** The PatchIQ postmortem's secrets lesson is enforced
by machine, not by good intentions: a pre-commit hook refuses the commit, and a scan target (the CI
gate, wired in by the CI ticket) fails the build if one ever lands anyway.

## What enforces it

| Layer | Where | Catches | Bypassable? |
| --- | --- | --- | --- |
| Pre-commit hook | `.githooks/pre-commit` → `gitleaks git --staged` | secrets in the staged diff, before they enter history | Yes (`--no-verify`), by design — hooks are advisory |
| Scan target | `make secrets-scan` → `tools/secrets/scan.sh` | every commit reachable from any ref **and** every tracked/untracked-not-ignored file on disk | No — CI runs it and a failure blocks the merge |
| Proof | `make secrets-test` → `tools/secrets/test.sh` | the above actually fail on a fake AWS key and a literal lab credential, and pass on clean input | — |

`gitleaks` is pinned (`tools/secrets/gitleaks.version`) and downloaded checksum-verified
(`tools/secrets/gitleaks.sha256`) into a per-user cache (`~/.cache/activediq/gitleaks/<version>/`,
or `$ACTIVEDIQ_TOOLS_DIR`). The wrapper refuses any binary whose version differs from the pin, so a
local "clean" means what CI's "clean" means. If gitleaks is missing the hook **fails closed** and
prints `make secrets-install`.

## Config: `.gitleaks.toml`

- Extends the upstream default ruleset (cloud keys, tokens, private keys, generic high-entropy
  assignments…).
- Adds `activediq-lab-credential`: a literal `LAB_*_PASSWORD/SECRET/TOKEN` value. Lab credentials
  are generated per run into the gitignored `lab/.lab.env`; reading one from the environment or
  generating it (`$(…)`, `${…}`) is fine, pasting a value is not.
- **Allowlist policy — provably fake values only.** Today that is the two AWS documentation example
  values and nothing else. There are **no path allowlists**: a path exemption hides a real secret
  pasted into it. Rules:
  1. Prefer building a fake secret at test runtime (as `tools/secrets/test.sh` does by splitting the
     literal across a `printf`) over allowlisting anything.
  2. A new allowlist entry is a *value* published as an example by its vendor (cite the URL in a
     comment) or a value in a fixture that is structurally invalid as a credential. Each entry
     carries a comment explaining why it is fake.
  3. Never allowlist a rule, a directory, or a real config file. Never use `gitleaks:allow` inline
     comments on anything that is not already an allowlisted fake.
  4. Allowlist changes need `security-architect` review (security-sensitive ticket tag).
- Gitignored files (`.env*`, `lab/.lab.env`, `*.pem`, `*.key`) are out of scope for the scan: they
  are where secrets may live, and git never sees them.

## When a secret is found

1. **Rotate/revoke it first** — assume it is compromised the moment it was committed or pushed.
2. Remove it from the tree; if it reached history, rewrite history only with the CEO's/director's
   say-so (shared branches), then re-run `make secrets-scan`.
3. Do **not** paper over a true positive with an allowlist entry. File a ticket if the cause was a
   process gap.
4. A false positive on a real-looking value is fixed in `.gitleaks.toml` by the narrowest value
   regex, under the policy above.

## Operating it

Runbook: `knowledge/development/runbooks/secret-scanning.md`.
