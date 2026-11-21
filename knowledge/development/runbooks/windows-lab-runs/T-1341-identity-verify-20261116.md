---
title: "T-1341 gap check on dc1: ForAccount enrol/repin by an elevated administrator (main, T-2215 ruling)"
date: 2026-11-16
status: draft
owner: windows-engineer
ticket: T-1341
---

RESULT: PASS. `lab/windows/bin/identity-verify` on dc1 (Windows Server 2025, one DC, no gMSA, no MSI). Full log:
`factory/demos/evidence/T-1341/gapcheck-dc1.log` (icacls before/after each step).

- AC1: elevated Administrator `Enroll(ForAccount)` then `Repin(ForAccount)`; the service-side `Load` as the real virtual account
  succeeds before and after, and the pin changes. Unit-level 4102 actor: TestRepinAuditNamesActor. `agentsetup.exe repin` was not run end to end (needs a live gateway).
- AC2: restricted token (Administrators deny-only, no privileges): list, read key.pem, overwrite the pin and create a sibling under the parent are all denied by the DACL; Repin and Enroll are refused and the listing and icacls equal the post-enrol dump. In a restricted token the account name does not resolve, so the verb refusals alone are weaker; the raw denials are the DACL proof. A real non-admin user was not available (a DC has no local users).
- AC3: every DACL is service + SYSTEM + BUILTIN\\Administrators; owner Administrators; no invoking-user SID.
