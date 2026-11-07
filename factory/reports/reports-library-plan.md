---
title: Reports library plan (batches 1-10b) and counts
date: 2026-11-07
owner: project-manager
tickets: T-1091 (first plan), T-1118 (grooming against the T-1015 spec)
---

# Reports library plan

T-1091 recorded this file as written on 2026-10-31, but it never reached `main`; T-1118 recreates it
from the ticket notes and the T-1015 spec (`knowledge/product/specs/reports-2-second-slice.md`, §2 and
§10). Row IDs, columns, filters and ME names come from the spec; this file only orders and counts.

## Batches

Library batches share `internal/modules/reports/library` (LOCK, crosswalk.tsv, `reports_library_matches_spec`),
so they run one at a time in batch order. Ground truth is the seeded Samba lab; **no ManageEngine match is
claimed** before the ADMP install (A-0024, T-0673); those checks are T-1116, T-1117, T-1120.

| Batch | Ticket | Data ticket | Reports (spec IDs) | ME names | State 2026-11-07 |
| --- | --- | --- | --- | --- | --- |
| 1-3 (reports-2a) | T-0960, T-0962, T-0971 | | 16 | 54 | done / in flight |
| 4 | T-1107 | T-1472 (replaces T-1106) | PWD-04 | 1 | ready |
| 5 | T-1110 | T-1109 | USR-06, GRP-05, CMP-03, CTC-02, OU-02 | 9 | ready |
| 6 | T-1112 | T-1111 | USR-07, USR-08, USR-09, USR-11 | 11 | ready |
| 7 | T-1113 | (T-1111) | USR-12, USR-13, GRP-06, CMP-04 | 5 | ready |
| 8 | T-1114 | D12 (with T-1114); contract T-1718 | SYS-01 | 2 | ready |
| 9 | T-1115 | (T-1111) | CMP-05 | 2 | ready (gate cleared: T-1014, T-1132) |
| 10 | T-1725 | T-1719 (D13 `inventory.printers`) | SYS-02 | 1 | ready |
| 10b | T-1726 | T-1721 decoder, T-1723 RPC (D14), T-1512 right, T-1720 contract | SYS-03 | 1 | ready, waits on its deps |
| | | | **New in slice 2 (4-10b)** | | **18 reports, 32 names** |

Per-batch splits of 18 and 32 are derived from spec §2/§3 and add to the spec's totals (1+5+4+4+1+1+1+1 = 18
reports; 1+9+11+5+2+2+1+1 = 32 names). Counts are firm: CMP-05 is no longer gated.

Supporting tickets for SYS-03 (Tier-0 adjacent, `security-sensitive`): T-1721 `replxml` decoder, T-1723
`ReadReplicationStatus` RPC, T-1724 fitness job RX1-RX6, T-1727 Windows-lab fixtures and CC-REPL-04/05/06,
T-1510 lab read of attribute location and minimum right, T-1512 RBAC permission and wizard ACE (TM-D31),
T-1720 API contract. UI: T-1514 (SYS-01), T-1515 (SYS-03). T-1722 (spec wording per TM-D31) lands before T-1726.

## Counts against the 60+ promise (PRD §8.2)

| Reading | After reports-2a | After this slice |
| --- | --- | --- |
| ME-named reports (presets the admin can name) | 54 | **86** |
| Report definitions | 16 | **34** |

The outward claim is **"60+ named reports"**, counted by ME name, and the claim must say so. Counted
by definition the library holds 34, below 60. The ME-name count clears 60 with margin and is all firm
(32 of 32 new names); the floor if batches 5 and 6 slipped (20 names) is still 66.

## ADM-092 (spec §2, §7)

| ME name | Disposition | Ticket |
| --- | --- | --- |
| Password Policy, Account Lockout Policy | Specced, batch 8 | T-1114 |
| Printer Reports | Specced as "Published printers", batch 10 | T-1719, T-1725 |
| DC Replication Status | Specced, batch 10b, read-only, optional right (TM-D31) | T-1721, T-1723, T-1512, T-1726 |
| Lingering Objects | **Kept out**: LDAP cannot prove it; detection is `DsReplicaVerifyObjects` on Windows and ME's version can delete (Tier-0 write). The slice ships only the "risk indicator" column inside SYS-03. No build ticket until T-1121 (spec, done) is reviewed by security-architect (T-1564) and the director schedules it | T-1121, T-1564 |

Also kept out (spec §8): Terminal Services 2 (decoder spec T-1122; build T-1566, USR-10), BitLocker 3, GPO OUs 2.
Each is 0 in the counts above; Terminal Services would add 2 names if T-1566 ships.

## Risks

| Risk | L x I | Mitigation | State |
| --- | --- | --- | --- |
| "60+ reports" read as 60 definitions: library has 34 | M x M | State the claim as "60+ named reports" on every outward surface; owner product-manager to confirm the reading | accepted, claim wording is the mitigation |
| SYS-03 chain is long and ends on the Windows lab (T-1510, T-1727); a lab outage delays batch 10b only | M x L | 10b is last; nothing else waits on it | accepted |
| Batches serialise on one package, so one slow batch holds the rest | M x M | Batch order is fixed; a stuck batch goes to the director rather than being skipped | accepted |
| T-1112 text still names Terminal Services | L x L | Note on T-1112; acceptance 1 (equals spec rows) governs | mitigated |
