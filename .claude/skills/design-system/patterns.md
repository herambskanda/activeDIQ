# activeDIQ pattern library

Each pattern: when to use it, the rules, and the states it must render. Directory sizes to
design for: 100k+ users, 10k-member groups, forests with several domains.

## Server-side data table

**Use for** every list of users, groups, computers, OUs, GPOs, audit events, report rows.

- **All paging, sorting and filtering happen on the server.** The client never loads a whole
  directory. Paging is cursor-based; show "1–50 of 12,431" (count may be "≈" if the server says
  it is estimated — say so).
- Table state (filters, sort, columns, page) lives in the URL, so views are shareable and the
  back button works.
- Filter bar: free-text search (name, `sAMAccountName`, UPN, mail) + typed filter chips
  (OU/container, enabled/disabled, locked, last logon older than, member of). Filters compile
  to safe LDAP filters **on the server** — the UI never sends raw filter strings.
- Saved views per user; a few shipped defaults (e.g. "Locked out", "Inactive 90 days").
- Column chooser; DN, SID and GUID columns in mono with copy-on-click; long DNs truncate in the
  middle with the full value on hover.
- **Selection**: checkbox per row; header checkbox selects the page; then a banner offers
  "Select all 12,431 matching". Bulk actions act on the *query*, not a list of IDs the client
  holds, and the impact preview re-evaluates it.
- **Bulk action bar** appears on selection: count, the actions this role may perform on the
  selection, "Clear".
- Row click opens the side drawer; `Enter` on a focused row opens the detail page.
- Export (CSV, XLSX) runs as a job for > 10k rows, with a notification when ready.
- States: loading (skeleton rows, header stays), empty-no-data, empty-no-match (show the active
  filters and "Clear filters"), error (keep last good data, banner with retry), partial (one
  domain unreachable: rows from the others plus a warning naming the domain).

## Object detail page

- **Identity header**: display name (h3), object type, key identifiers in mono (`sAMAccountName`,
  UPN, DN with copy), status badges (Enabled/Disabled, Locked, Password expires in N days,
  Tier-0, Synced from on-prem). Primary actions on the right — the role's 2–3 most common —
  the rest under "More".
- Tabs: **Overview** · **Attributes** (all, searchable, friendly + LDAP name, edit inline where
  allowed) · **Membership** (direct and nested, with the path) · **Activity** (audit trail, §
  Audit) · **Permissions** (who can manage this object, and why) · type-specific tabs
  (Mailbox, Devices, Licences).
- Source of authority visible for hybrid objects: an attribute mastered on-prem is read-only
  in the Entra view, with the reason.

## Side drawer

- Opens from the right over the list; the list stays visible and keeps its scroll and
  selection. Width 480–640 px. Deep-linkable (`?drawer=<objectId>`).
- For quick view and edits of ≤ ~6 fields. Anything larger opens the detail page.
- `Esc` closes; unsaved changes prompt before closing. Focus moves into the drawer and returns
  to the row on close.

## Command palette and search-first navigation

- `⌘K` / `Ctrl+K` anywhere. One box finds objects (name, `sAMAccountName`, UPN, mail, SID,
  GUID), pages and actions ("Reset password for…", "Unlock…").
- Results grouped by type, keyboard-only operable, show the DN in mono to tell same-named
  objects apart. Actions respect permissions (§ Permission-aware) — no action the user cannot
  run.
- Global search is the primary way in; deep menu trees are the anti-pattern we displace (see
  the ADSelfService Plus admin-experience notes in `knowledge/business/market-research/`).

## Wizard

- For 3+ dependent steps: create user from template, CSV import, delegation setup, migration.
- Step list on the left with completion state; Back never loses data; a draft persists if the
  user leaves.
- Validate per step; the **last step is always Review**, which is an impact preview (below).
- The wizard ends on a result page with per-object outcomes and links to the audit entries.

## Inline validation

- Validate on blur and on submit, not on every keystroke (except length counters).
- Directory rules are checked by the **server** against the target domain: `sAMAccountName`
  ≤ 20 characters and its forbidden characters, uniqueness (UPN, `sAMAccountName`, mail), the
  effective password policy (FGPP or domain policy) for that user. Show the rule that applies,
  e.g. "Must be 14+ characters (policy: Tier1-Admins)".
- Error text sits under the field, `--sk-crit` with an icon, and is linked via
  `aria-describedby`. A summary at the top on submit links to each invalid field.

## Impact preview + confirmation

**Mandatory** for: any bulk operation; deletes; disables; moves; group membership removals;
password resets for more than one user; anything touching a Tier-0 object; GPO changes.

- **Dry run first.** The preview is computed by the server from the real directory, not
  guessed by the client.
- Shows: the count; a sample table of affected objects (the full list downloadable); a
  **before → after diff** per attribute; side effects (nested group effects, mailbox impact,
  licences removed, objects skipped and why); Tier-0 objects flagged at the top; what is **not
  reversible**.
- Confirmation: the button names the action and count ("Disable 1,204 users"). For > 100
  objects or any Tier-0 object, the admin types the count or the object name. Approval
  workflows (if configured) replace execute with "Submit for approval".
- Execution: a job with live progress, cancel (stops pending items), per-object results,
  "Retry failed", and export of results.

## Undo

- After a reversible change: a toast with **Undo** (10 s) and a link to the audit entry; the
  audit entry keeps a **Revert** action afterwards (permission-checked, previewed like any
  change).
- Reversible: attribute edits, group membership, OU moves, enable/disable. Not reversible —
  say so in the preview: password resets, hard deletes (soft-deleted objects can be restored
  only if the AD Recycle Bin is enabled — detect and say which).

## Empty, loading, error states

- **Empty**: what this place is for, and the one action that fills it ("No scheduled reports.
  Schedule a report"). Never sample data.
- **Loading**: skeletons that match the final layout, after 300 ms (avoid flash); long jobs
  show progress and can be left running.
- **Error**: what happened · likely cause · what to do · Details (DC, LDAP result code, Graph
  error, trace ID (`traceId`)) · Retry. Distinguish *no permission*, *not found*, *directory
  unreachable*, *validation*, *our bug*.

## Audit-trail visibility

- Every change made through activeDIQ shows **who · when · what (before → after) · why
  (reason or ticket ref) · how (UI, API, PowerShell, workflow) · approval** on the object's
  Activity tab and in the global audit log.
- Changes made outside activeDIQ (native tools) appear too once collectors exist, marked with
  their source.
- Success toasts and job results link to their audit entries.

## Permission-aware UI

- The server is the only enforcement point; the UI reflects it.
- **Hide** what the role can never do in this scope. **Disable with a reason** (tooltip, and
  in the accessible name) what is temporarily unavailable ("Account is Tier-0: requires
  Tier-0 operator role").
- **No dead buttons**: never render a control that will fail with 403. A 403 that reaches the
  UI anyway is a bug, and the error state says which permission was missing.
- Delegated scope is visible: "Scope: OU=Sales,DC=lab,DC=activediq,DC=test" in the header for scoped
  roles.
