---
title: "Runbook: secret scanning (gitleaks)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0013
---

# Runbook: secret scanning

Policy and design: `knowledge/development/standards/secret-scanning.md`.

## 1. Set up (once per clone; worktrees share it)

```bash
make secrets-install-hooks   # sets core.hooksPath=.githooks and installs the pinned gitleaks
```

`core.hooksPath` lives in the shared `.git/config`, so it applies to every worktree **after** the
branch containing `.githooks/` is merged into it. The installer refuses to overwrite a different
existing `core.hooksPath`; chain `.githooks/pre-commit` from it instead.

Only need the binary (e.g. a CI runner)? `make secrets-install`. Supported: macOS and Linux,
arm64/x64. On other platforms install gitleaks at exactly the pinned version onto `PATH`.

## 2. Everyday

- Committing: the hook scans the staged diff. A refusal prints the rule, file and line (the secret
  itself is redacted). Fix the file; do not `--no-verify`.
- `make secrets-scan` — full history + working tree. Exit 0 = clean. This is the CI gate command.
- `make secrets-test` — proves the gates fail on a fake AWS key and a literal lab credential and
  pass on clean input (14 checks, throwaway repo, ~10 s). Run it whenever `.gitleaks.toml`, the hook
  or the scripts change.

## 3. Upgrading gitleaks

1. Check the new release's licence is still MIT; update the register row.
2. Put the new version in `tools/secrets/gitleaks.version` and replace `gitleaks.sha256` with the
   upstream `gitleaks_<ver>_checksums.txt` lines for the four supported archives.
3. `make secrets-install secrets-test secrets-scan` — new default rules can flag old content; triage
   per the standard (never blanket-allowlist).

## 4. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `gitleaks 8.x.y not found. Run: make secrets-install` | not installed, or the binary on `PATH` has a different version than the pin |
| `CHECKSUM MISMATCH` | download tampered or corrupted — do not proceed; retry on another network and tell security-architect if it persists |
| Hook does not run | `git config core.hooksPath` is not `.githooks` (run `make secrets-install-hooks`), or the branch predates the hook |
| Finding in a doc example | use the vendor's published example value (allowlisted) or build it at runtime; do not allowlist a path |
