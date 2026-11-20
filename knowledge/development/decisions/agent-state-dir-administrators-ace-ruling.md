---
title: "Ruling: an Administrators ACE on the agent state directory is accepted (main's ForAccount); T-1341's no-Administrators mechanism is dropped"
date: 2026-11-16
updated: 2026-11-16
status: accepted
owner: security-architect
kind: technical
ticket: T-2215
fitness: ownerfile Windows tests TestWindowsForAccountNamesAccountNotCaller, TestWindowsForAccountUnknownAccountFailsBeforeWriting (lab, dc1); new tests required below
---

# Ruling: Administrators ACE on the agent state directory (T-2215)

## Decision

**Option 1.** Accept main's mechanism from T-1249: `ownerfile.ForAccount` / `dial.ForAccount` / `TrustAdministrators`.
The state directory is owned by `BUILTIN\Administrators`; its protected DACL grants SYSTEM, Administrators and the service
account (`NT SERVICE\activeDIQAgent`), never the invoking user's SID. T-1341's branch (`af128ccfb`, mechanism b: service+SYSTEM-only
DACL, SeBackup/SeRestore, elevation gate) is **dropped**; T-1341 reduces to a gap check on main (below).

## Reasoning

1. **The property T-1315 protected does not exist on a DC.** T-1315 omitted Administrators so an admin would not read `key.pem`
   "by membership". The agent runs on domain controllers, where local Administrators is Domain Admins/Enterprise Admins. That
   population can already run as SYSTEM, read the service's memory, take ownership or use SeBackup. `key.pem` is the agent's
   mTLS client key, not a domain secret: its loss lets an attacker impersonate one agent to the server, and the same admin
   could already do that from the process. The ACE adds no capability an administrator lacks.
2. **The "audit trail" the old text promised is thin.** fleet-contract.md said take-ownership leaves events 4674/4670 "only where
   the audit policy captures it". T-1341 itself reads through SeBackup with `BACKUP_SEMANTICS`, which bypasses the DACL and
   leaves no such trail. Neither design gives a reliable record of an admin reading the key; the human actor is recorded where it
   matters, in the 4102/4103 repin events.
3. **ADR-0006 rule 5 already specifies it.** The data-directory DACL is "service SID, SYSTEM, Administrators, nothing else"
   ([ADR-0006](0006-dc-agent-runs-as-a-virtual-service-account.md)). The T-1315 fleet-contract text was the outlier. The
   ADR governs; fleet-contract.md is corrected.
4. **Smaller Tier-0 attack surface.** T-1341 enables SeBackup/SeRestore process-wide for the `Dir` lifetime, and its own review
   recorded the residual: any `os.Open` of an input-derived path inside that window bypasses DACLs (Go sets
   `FILE_FLAG_BACKUP_SEMANTICS`). ForAccount uses ordinary file access checks and no privilege. A plain DACL is what we can
   verify with `icacls`, and it is already merged, lab-run on dc1 (T-1249) and shared with the service's own `Load`.
5. **Cost.** Keeping T-1341 means removing ForAccount/TrustAdministrators from six-plus files, porting 13 conflicting files and
   re-running identity-verify on dc1, to remove an ACE that gives no real protection.

## Conditions (what stays true, and what T-1341 must now check)

1. The ACE is the **Administrators group** SID only. No invoking-user SID, `Users`, `Authenticated Users` or `Everyone` is ever
   granted; the DACL is PROTECTED; typed ACEs only, never SDDL.
2. The agent service never holds SeBackup/SeRestore/SeTakeOwnership (ADR-0006 rule 3); `TrustAdministrators` only widens what
   the service accepts on read, never what a plain write produces (`principals.sids()`).
3. Gap check T-1341 AC1-AC3 on main, evidence on dc1 with `icacls` before/after:
   - **AC1.** Elevated admin repin succeeds, the service's next `Load` succeeds with the new pin, and the 4102 event names the admin.
     The earlier branch proved the actor at unit level only; run `agentsetup.exe repin` end to end once a gateway is mounted.
   - **AC2.** A non-admin (a restricted token, as on the old branch, since a DC has no local users) is refused for repin **and**
     enrol, and the directory listing and `icacls` are unchanged. This relies on the DACL, not on a code gate; if it fails, add a
     small explicit elevation check (Administrators enabled, not deny-only, plus `IsElevated`) in `agentsetup`, which is the
     one part of T-1341 worth porting. Do not port the privilege handling.
   - **AC3.** No file or directory ACE or owner names the invoking admin's user SID (`TestWindowsForAccountNamesAccountNotCaller`
     plus a DACL dump).
4. fleet-contract.md "One principal set" and "Enrol identity" bullets are rewritten to match ([architecture/fleet-contract.md](../architecture/fleet-contract.md) lines ~239-243, 261): owner Administrators; SYSTEM, Administrators and service account; the
   Administrators ACE is accepted per this ruling. Remove the sentence about admins "taking ownership deliberately".
5. gMSA stays out of scope (ADR-0006 rule 1 forbids it); ForAccount resolves any account name, so that is a policy, not a code, constraint.

## Residual risk

A local administrator reads or replaces the agent's key and pin by group membership. Accepted: the same person is Tier-0 on the
DC. Server-side, a replaced agent key shows as a leaf/identity anomaly; revoke by re-enrolment. Customer-visible only as "DC
administrators can read the agent's client key", worth one line in the security whitepaper; not a directional CEO decision.
