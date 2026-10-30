---
title: Release publication and security.txt renewal
date: 2026-10-27
updated: 2026-10-27
status: draft
owner: devops-engineer
ticket: T-0261
---

# Release publication and security.txt renewal

Follow-up of D-0004 a (`../decisions/security-commitments-first-release-prep.md`). Three small tools under
`tools/release/`, standard library only (no licence-register row needed), two GitHub workflows, one gate.

## security.txt renewal (`.github/workflows/security-txt-renewal.yml`)

- Runs weekly (Monday 06:17 UTC) and on demand (`workflow_dispatch`).
- `go run ./tools/release/renewsecuritytxt -write` sets `Expires` to ~330 days ahead when it is under 90 days
  away, expired, or unparseable; it refuses a file without exactly one `Expires`.
- When it changed the file, the job pushes `chore/security-txt-renewal-<date>` and opens a pull request.
  That is at least 60 days before `make fitness-disclosure` goes red (30 days before Expires).
- A PR opened with the workflow token does not start other workflows. Review it, read `SECURITY.md` for
  stale content, run `make ci` locally or on the branch, merge.
- If the repository forbids Actions from creating PRs (Settings, Actions, General), the job fails: allow it,
  or run the tool by hand. A failing job is the signal; do not mask it.

## Signed release (`.github/workflows/release.yml`)

On a `v*` tag it produces and publishes, on the GitHub release:

| File | What |
| --- | --- |
| `activediq-<tag>.cdx.json` | CycloneDX 1.5 SBOM: Go modules the `./cmd/...` binaries import, plus non-dev packages of `web/package-lock.json` (with lockfile hashes). Reproducible: `SOURCE_DATE_EPOCH` is the commit time |
| `SHA256SUMS` | checksums of the release files (installer and binary artefacts join when packaging produces them) |
| `*.sig` | detached Ed25519 signatures (base64) of the SBOM and of `SHA256SUMS` |

The job verifies each signature against `packaging/release/release-signing.pub` before `gh release create`.
No secret, no committed public key, or a mismatch fails the job; nothing is published unsigned. The offline
courier ships the same files (same bundle, different courier).

Verify by hand: `go run ./tools/release/sign verify -pub packaging/release/release-signing.pub -sig SHA256SUMS.sig SHA256SUMS`.

## One-time setup (not done by this ticket: key custody and anything creating accounts is a CEO/security matter)

1. security-architect generates the pair on a trusted machine: `go run ./tools/release/sign keygen`.
2. The `seed` goes into the repository secret `RELEASE_SIGNING_KEY` (Settings, Secrets); never a file, a log or an argument.
3. The `public` value is committed as `packaging/release/release-signing.pub`.
4. Rehearse with a throw-away tag on a fork. This key is **interim**: production custody (offline root, HSM/KMS,
   TUF metadata, Authenticode) is T-0140/T-0141 and replaces the key source, not the file layout. Rotate by
   replacing the secret and the committed public key in one change.

## Gates and proof

`make workflows-check` (in `make ci`): no `continue-on-error`, every `uses:` pinned to a commit SHA, `release.yml`
verifies what it signs. Failing cases for it and for the three tools are in `tools/ci/proof.sh` (`make ci-proof`);
unit tests run in `make test`.
