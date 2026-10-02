# Top 20 admin tasks — the benchmark set

Provisional: `product-manager` owns this list and revises it when the v1 scope lock lands
(`knowledge/business/scoping/`). Tasks outside the locked scope are skipped, not deleted.
Parity IDs: take them from the matrix or research files — none are pre-filled here, so none are
invented. Measurements go to `knowledge/product/design-system/task-benchmarks.md` (see
SKILL.md §3).

Each task starts on the product's landing page, signed in, target object not open. "Done" is
the state named in the last column, verified in the directory.

| # | Persona | Task | Done when |
| --- | --- | --- | --- |
| 1 | Help desk | Reset a user's password and unlock the account, force change at next logon | `pwdLastSet` = 0, `lockoutTime` = 0 |
| 2 | Help desk | Unlock a locked-out account (no reset) | `lockoutTime` = 0 |
| 3 | Help desk | Find a user by partial name or employee ID and open it | Detail page shown |
| 4 | AD admin | Create one user from a template (OU, groups, attributes) | User exists with template groups |
| 5 | AD admin | Bulk-create 50 users from CSV with a dry run | 50 users exist; errors reported per row |
| 6 | AD admin | Offboard a leaver: disable, remove groups, move to leavers OU, set description | All four applied, audit entry linked |
| 7 | AD admin | Add one user to three groups | Memberships present |
| 8 | AD admin | Bulk-modify an attribute (e.g. `department`) for 1,000 users with preview | Values changed; preview count = result count |
| 9 | AD admin | Move 20 computers to another OU | Objects in target OU |
| 10 | AD admin | Create a security group and add members by CSV | Group with members |
| 11 | AD admin | Find users inactive > 90 days and disable them | Disabled; report exported |
| 12 | AD admin | Restore a deleted user (Recycle Bin enabled) | User restored with memberships |
| 13 | AD admin | Delegate "reset password + unlock" for one OU to a help-desk role | Scoped role can do 1–2 in that OU only |
| 14 | SOC analyst | Who changed membership of Domain Admins in the last 7 days? | Events listed with who/when/before→after |
| 15 | SOC analyst | Find the source of repeated lockouts for a user | Source computer/DC identified |
| 16 | Auditor | Export all privileged-group members with last logon, as of today | File exported |
| 17 | Auditor | Schedule a monthly report emailed to a distribution list | Schedule saved; test send received |
| 18 | IT manager | Approve a pending workflow request (group-membership request) | Request executed, audit shows approver |
| 19 | End user | Reset forgotten password via the self-service portal (enrolled, MFA) | Can sign in with new password |
| 20 | End user | Enroll for self-service (two factors) | Enrollment recorded |

For bulk checks (5, 8, 11) also run the 10k-object variant: 10,000 objects selected via "select
all matching", preview, execute, cancel half-way, retry failed.
