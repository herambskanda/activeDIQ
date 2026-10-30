---
title: unicodePwd vectors PW-04, PW-14, PW-09 — Samba vs Windows lab results
status: draft
owner: test-engineer
ticket: T-0074
---
# unicodePwd vectors PW-04 / PW-14 / PW-09 (T-0074, 2026-10-28)

Spec: `knowledge/development/architecture/safe-primitives.md` password vector table (§ lines ~753-770).
Tests: `internal/connector/ad/unicodepwd_lab_test.go` (shared body), `…_samba_lab_test.go`, `…_windows_lab_test.go`.
The product has no unicodePwd encoder yet; the tests use a test-owned reference encoder (quoted UTF-16LE) and
raw LDAP Modify over verified LDAPS, then **bind as the user** to prove what the DC stored.

Run: Samba `make lab-up && go test -tags lab -run TestLabUnicodePwd -v ./internal/connector/ad/`;
Windows (VM 119, dc1) `make lab-test-connector-windows` (the `^TestWindowsLab` filter includes `TestWindowsLabUnicodePwdVectors`).
Windows run used the main checkout's gitignored lab env/CA with `WIN_LAB_DC_ADDR=192.168.1.9`.

| Vector | Samba (lab) | Windows Server 2025 | Differs |
| --- | --- | --- | --- |
| Encoded bytes PW-04 `a"b`, PW-14 `"abc"` | match spec table | match | no |
| PW-04 literal `a"b` | 19 ConstraintViolation `0000052D` (too short, <7) | 53 UnwillingToPerform `0000052D` DSID-031A12C5 | **result code** (policy refusal either way) |
| PW-14 literal `"abc"` | 19 ConstraintViolation (too short) | 53 UnwillingToPerform | **result code** |
| PW-04 policy-compliant `Zq"7-Lm2xWvB9!k` | set (0); bind with exact password ok; quote-stripped/truncated binds fail | same | no |
| PW-14 policy-compliant `"Zq7-Lm2xWvB9!k"` | set; bind with exact password (outer quotes kept) ok; stripped bind fails | same | no |
| PW-09 256 UTF-16 units | accepted, bind ok | accepted, bind ok | no |
| PW-09 257 UTF-16 units | **accepted** (0) | refused 53 UnwillingToPerform | **YES — Samba divergence** |

## Findings
1. PW-04 / PW-14: both DCs treat inner quotes as data and store the exact password. The literal spec passwords
   are shorter than the lab policy, so they are refused on policy; the compliant variants prove the quote semantics.
   The spec's `[UNVERIFIED — lab]` tags can be lifted (spec change filed as a follow-up, not edited here).
2. PW-09: Windows refuses 257 units and accepts 256, so the provisional cap of 256 matches Windows exactly.
   **Samba accepts 257**; the product cap, not the DC, must produce `TooLong` on Samba. The Samba test pins this
   divergence (`acceptsOverCap`) and fails if Samba changes.
3. Diagnostics differ: Samba 19 + readable text; Windows 53 + `DSID` and no text (safe-primitives gotcha 52).
   PW-13's "DC answers 19/53 with 0000052D" holds on both.
4. Proof the tests bite: replacing the encoder with one that strips inner quotes fails the byte-table test and both
   compliant-variant tests on Samba.
