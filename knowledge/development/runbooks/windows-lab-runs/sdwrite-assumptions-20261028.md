---
title: sd.write assumptions on a Windows DC — SDProp, PD-clear, INHERITED, DACL-only SD_FLAGS (T-0606)
status: draft
owner: test-engineer
ticket: T-0606
---
# sd.write assumptions verified on Windows Server 2025 (T-0606, 2026-10-28)

Tests: `internal/connector/ad/sdwrite_windows_lab_test.go` (`TestWindowsLabSDWrite*`, tags `lab windowslab`), written
through the product's own `sd.PlanDACL` / `sd.PlanInheritance`, sent over verified LDAPS with the planner's own
control, read back with the DACL-only SD_FLAGS control. Full log: `sdwrite-assumptions-20261028.log` (ACE lists
elided; SIDs are lab-domain SIDs).
Run: `make lab-test-connector-windows` (the `^TestWindowsLab` filter includes them), or
`WIN_LAB_DC_ADDR=<dc> go test -tags 'lab windowslab' -run TestWindowsLabSDWrite -v ./internal/connector/ad/`.
Lab: Windows Server 2025 DC `192.168.1.9` (VM 119), forest `win.activediq.test`, ~1–3 s per full run (SDProp is
triggered on demand via rootDSE `runProtectAdminGroupsTask`; waits are condition polls with a 90 s bound).
Fixtures are created under `OU=Managed` and deleted as Administrator, so a re-run is clean (3 consecutive passes).

| AC | Assumption | Result | Corpus |
| --- | --- | --- | --- |
| 1 | A DACL write on an SDProp-protected object is reverted (SD-E11) | **Holds.** A new Account Operators member became `adminCount=1`, PD set, DACL = AdminSDHolder after SDProp. The DC *accepted* a planned DACL write on it (so the planner's refusal is not redundant); the next SDProp run removed the ACE. A `RestoreInheritance` (PD cleared) on it was also undone (PD back). Revert was triggered on demand, so the ~60 min interval is **not** verified. | SD-E11, SD-W16 → `windows` |
| 2 | PD cleared ⇒ DC recomputes inherited ACEs (RestoreInheritance) | **Holds.** PD child received nothing while PD (canary sibling proved propagation ran); after the PD-clear write the DC added the inherited copy of the parent's later ACE and PD was cleared, DI kept. Old explicit copies (from BlockKeep) are *not* de-duplicated: after Restore the child holds both the explicit and the inherited copy of the same ACE. | SD-W12 → `windows` |
| 2 | BlockRemoveInherited | **Holds.** PD set, all inherited ACEs gone, explicit ACEs identical and in order. | SD-W11 → `windows` |
| 2 | BlockKeepInherited | **Partly diverges.** PD set, inherited → one explicit copy each, ACE multiset identical, **but the DC re-sorted the DACL** (former inherited ACEs moved ahead of the explicit ones). SD-W10 says "order kept". | SD-W10 stays `doc`; **T-0627** |
| marker | INHERITED survives a DACL write | **Holds.** After an explicit add the inherited ACEs keep INHERITED and DI. Even with DI cleared in the client's control word the DC kept the markers and DI (recomputed), so "copy, don't compute" is not needed for Windows (Samba differs per the ixsystems note; not retested). | — |
| marker | Stored order = planned order | **Diverges.** A planned plain allow inserted ahead of the object allows is stored after them (default DACLs list object ACEs first). Effective rights are unaffected for allow-only moves, but verify-after-write (SD-R10) must not compare by position. | **T-0627** |
| 3 | DACL-only SD_FLAGS write needs no SeSecurityPrivilege, owner/group/SACL unchanged | **Holds.** `svc-activediq` (cannot read the SACL; flags 8 returns none) wrote a DACL-only value with offsets 0 on an object with a 2-ACE SACL; read back as Administrator (flags 15): owner, group and SACL byte-identical, ACE added. The same bytes under SD_FLAGS=15 are refused (code 50), which is why the control stays DACL-only. | SD-E12, SD-E12B → `windows` |
| 4 | OWNER RIGHTS (T-0583 r3 note) | Owner = connector, all other WRITE_DAC routes removed. No ACE: owner writes DACL. **OWNER RIGHTS ACE applying to the object: refused (50)**, as MS-DTYP says. **Inherit-only (CI\|IO) OWNER RIGHTS ACE: owner still writes. Inherit-only owner-SID ACE: owner still writes.** So SD-W26/W27 are conservative on this DC version; narrowing needs a security decision. | SD-W26/W27 stay `doc`, **kept fail-closed deliberately (T-0628)** |

## Not covered / limits
- One DC, one OS build (WS2025). Samba not rerun. SDProp interval (60 min) and PDC-emulator-only behaviour unverified.
- T-0627: the expected-to-fail marker is now a strict `DACLWrite.VerifyAfter` assertion (`verifyAfter` in the test). **Not yet run on the Windows lab**; T-0727 owns the run. VerifyAfter fails closed on any inverted allow/deny pair with overlapping masks, so it may reject a real BlockKeepInherited re-sort that moves a deny ahead of an allow — T-0727 must record that output.

## Proof the tests bite
Temporarily breaking `PlanInheritance` (no PD set/cleared) made `TestWindowsLabSDWriteInheritance` fail in three
places (`BlockKeepInherited: PD not set`, `BlockRemoveInherited: expected PD…`, `PD child received the parent's ACE`);
planner restored (`git status` clean for `internal/directory/sd`).
