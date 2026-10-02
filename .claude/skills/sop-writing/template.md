---
title: "SOP: <Procedure name, imperative>"
date: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft                 # draft → review → accepted | superseded
owner: heramb
author: <agent>
applies_to: "activeDIQ >=<version>"
rehearsal: pending            # pending | passed YYYY-MM-DD | blocked — <ticket or D-id>
---

# SOP: <Procedure name>

## 1. Purpose

What this procedure achieves, when to run it, and what it must never be used for. Expected
total duration. **Point of no return:** step <n> / none.

## 2. Scope

- Applies to: <environments, product versions, directory types (AD on-prem / Entra / hybrid)>
- Does not apply to: <…> — use <other SOP> instead.

## 3. Roles

| Role | Who | Responsibility in this SOP |
| --- | --- | --- |
| Operator | <agent or customer admin role> | Runs the steps |
| Approver | <role> | Approves step <n> (⚠ Change on Tier-0) |
| Escalation | <role> | See §8 |

## 4. Prerequisites

- [ ] Access: <activeDIQ role>; <AD rights, least privilege>; <host access>
- [ ] Secrets: <secret-store entry names — never values>
- [ ] Tools and versions: <PowerShell 7.x with RSAT AD module / curl / …>
- [ ] State: <backups taken, maintenance window agreed, replication healthy (`repadmin /replsummary` clean)>
- [ ] Placeholders:

| Placeholder | Meaning | Example (lab) |
| --- | --- | --- |
| `<DC_HOST>` | Writable DC in the target site | `dc1.lab.activediq.test` |

## 5. Procedure

1. **<Action>.**

   ```powershell
   Get-ADDomainController -Identity '<DC_HOST>' | Select-Object HostName, Site, IsGlobalCatalog
   ```

   **Expected result:** one row, `IsGlobalCatalog` = `True`.
   If not: go to §8.

2. **⚠ Change — <action>.** Changes: <what, on which objects>. Reversible: yes (§7 step R2) / no.

   Pre-check: <dry run / -WhatIf / impact preview> → **Expected result:** <count, list>.

   ```powershell
   $params = @{ Identity = '<SAM_ACCOUNT_NAME>'; Enabled = $false }
   Set-ADUser @params
   ```

   **Expected result:** <…>

3. …

## 6. Verification

How to prove the procedure achieved its purpose, independent of the steps above (a report, a
query, a user test). Each check with its expected result.

## 7. Rollback

| Step | Undo | Expected result |
| --- | --- | --- |
| R2 (for step 2) | <command> | <…> |

When to roll back: <trigger conditions>. Who decides: <role>.

## 8. Escalation

| Situation | Contact / ticket | Information to include |
| --- | --- | --- |
| Expected result not met at a ⚠ step | <role / support tier> | Step number, output, time, build |

## 9. Rehearsal record

| Date | Lab (tier) | Product build | Who (agent · run) | Result | Deviations fixed | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| | | | | | | `factory/demos/evidence/<ticket>/` |

## 10. Revision history

| Date | Change | Ticket | Re-rehearsed |
| --- | --- | --- | --- |
| YYYY-MM-DD | Created | T-… | yes |
