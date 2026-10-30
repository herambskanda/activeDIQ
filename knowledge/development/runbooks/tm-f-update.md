---
title: TM-F-UPDATE — a bad update is refused on either courier
date: 2026-10-29
updated: 2026-10-29
ticket: T-0139
status: draft
owner: devops-engineer
---

# TM-F-UPDATE: tampered, rolled-back, frozen, revoked-key or server-signed updates are refused

Proof for threat model §10 (TM-TB10-T1..T5, TM-TB12-T3) and ENH-07 AC-1..AC-8
(`knowledge/product/specs/enh-07-signed-update-protocol.md`). Subject: the one shared verifier,
`internal/platform/updateverify` (T-0645). The proof calls only its exported surface, as a courier does.

## Run it

| Command | What it does |
| --- | --- |
| `make fitness-update` (or `go run ./tools/fitness/update`) | Whole matrix through both couriers. Part of `make fitness` and `make ci`. |
| `make fitness-update-offline` | The offline-bundle courier again inside `docker run --network none` (static binary, read-only mount, digest-pinned image shared with the PostgreSQL fitness checks). Needs Docker. First proves the container cannot reach the network. |
| `go test ./tools/fitness/update` | The harness's own tests: matrix covers AC-1..AC-8 and every refusal reason; each broken verifier below is caught. |

## What is built, per run

Throw-away Ed25519 keys (nothing committed): a 2-of-3 root, timestamp, snapshot and targets keys, and the
server's own key, which is never in the root. Each scenario signs its own metadata and artefact, then a
courier delivers it: **online** (loopback HTTP GETs of static URLs) or **offline** (a tar bundle read as a
stream, no socket). Both end in the same `Verifier.Verify` call.

## The matrix (`tools/fitness/update/scenarios.go`)

| Scenario | AC | Expected |
| --- | --- | --- |
| accept-signed-release | 8 | accepted, committed 1.6, identical hash on both couriers |
| tamper-artefact-one-byte | 1 | `tamper` |
| tamper-manifest-hash / -length | 2 | `tamper` |
| tamper-overlong-artefact | 2 | `tamper`, at most 1 MiB of an 8 MiB stream read |
| tamper-metadata-after-signing | 2 | `tamper` |
| revoked-key-signs-targets | 3 | `revoked_key` |
| rollback-older-release / -older-metadata | 4 | `rollback` |
| rollback-after-database-restore | 4 | `rollback` (database half empty, host half holds 1.6) |
| freeze-expired-timestamp / -snapshot / -targets | 5 | `freeze`, with the expiry returned |
| freeze-clock-rewound | 5 | `freeze` |
| rotation-signed-by-old-threshold-accepted | 6 | accepted, next release signed by the new keys |
| rotation-below-old-threshold / -not-signed-by-new-keys | 6 | `unsigned_by_root` |
| server-key-signs-targets / server-supplied-root | 7 | `unsigned_by_root` |
| withdrawn-release | 7 | `withdrawn` |

Every refused scenario also asserts: the reason is exactly the expected one (not just "an error"); the
quarantine directory is empty; the data directory (where an extraction would land) is empty; no stray file
anywhere else in the sandbox.

## Why a green run means something

`-sabotage accept-all | mislabel | leak` runs the same matrix against a deliberately broken verifier
(refusals swallowed, every refusal relabelled `tamper`, a file written to the data dir before the
decision). `tools/ci/proof.sh` requires each to fail with its message, and requires the clean run to pass.
Mutating the real verifier (removing the rollback comparison, ignoring `Expires`) was also confirmed to
turn the run red, 8 and 12 problems, on T-0139.

## Operating notes

- A scenario that fails prints `<scenario>/<courier>: <what>`. Fix the verifier, not the case; changing a
  case's expected reason needs the ENH-07 spec section 8 audit reasons to change first.
- Adding a refusal reason to `updateverify.Reasons()` fails `TestMatrixCoversSpec` until a scenario uses it.
- The AC-9..AC-20 cases (SBOM, apply, HA, windows) are other tickets' proofs; AC-8's "no second verifier"
  test lives in `internal/platform/updateverify/ac8_test.go`.
- Real couriers (T-0553 and the bundle importer) must replace nothing here: when they land, point these
  fixtures' `deliver` functions at them, so the proof exercises the shipped transport.
