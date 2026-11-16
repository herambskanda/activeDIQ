---
title: "ADMP custom report builder: task cost and definition storage (ADM-097, MIG-05)"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: market-analyst
sources_last_checked: 2026-11-14
---

# ADMP custom report builder: task cost and definition storage

Ticket T-2102. Feeds `reports-2c-builder.md` §1, §4, §10. Extends
[manageengine-admanager-plus.md](manageengine-admanager-plus.md) (row ADM-097) and
[admp-8043-db-export-eula-findings.md](admp-8043-db-export-eula-findings.md); does not repeat them.
Source ranks: V = vendor help/docs, F = vendor forum, M = vendor marketing. Checked 2026-11-14.

## 1. Summary

| # | Question | Answer | Status |
|---|---|---|---|
| AC1 | Clicks/seconds to build a representative custom report | **No published timing or click count exists.** The documented procedure has a countable minimum of steps (§2), but wall-clock time is unmeasured. | seconds `[UNVERIFIED]`; lab step L-R1 |
| AC2 | How definitions and raw queries are stored; DB schema or export format | **Not found in docs as of 2026-11-14.** Vendor help does not describe storage, import or export of definitions (§3). Only generated *output* exports (§3). | `[UNVERIFIED]`; lab steps L-R2 to L-R4 |

## 2. Task cost: documented procedure (AC1)

Source: [ADMP help, Custom Reports](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html) (V, fetched 2026-11-14). Steps as documented:

1. Reports > Custom Reports. 2. **+ New Custom Report** (or **Copy Custom Report**); name and description.
3. **Add Report To** category. 4. **Select Directories**: AD domain + **Add OUs**, and/or an M365 tenant.
5. **Conditions** **+**: object type (users, groups, computers, contacts; M365 users only).
6. **Filters** tab: **LDAP Filter > Add Condition > Advanced Filter** (**Filter from Report**, or type in the **LDAP Query** field); **Refine Results > Add Condition** for database-level fields.
7. **Columns** tab (**Custom Attributes** for extra LDAP attributes). 8. **Management Actions** tab.
9. Optional **Preview Query**. 10. **Save**.

What this supports, and what it does not:

- **Counted:** a minimum of 10 documented UI steps, i.e. about 10 navigation/click groups before any typing. This is a *step count from docs*, not a measured click count: dropdown picks, OU tree selection and column ticks multiply it.
- **Not measurable from desk research:** seconds. We found no vendor, analyst or review source with a build time (searched 2026-11-14: vendor KB, community, blog; none gave a figure). Vendor marketing calls it creation "without complex PowerShell scripts" ([guide](https://www.manageengine.com/products/ad-manager/custom-reports-for-active-directory.html), M) which is not a measurement.
- **Typing burden:** the LDAP Query field takes a raw filter the admin must know and write ([ManageEngine blog, part 4](https://meblog.manageengine.com/active-directory/2018/02/06/admanager-plus-custom-reports-part-4-creating-custom-ldap-query-based-reports.html), M; the page returned HTTP 502 on fetch, so its content is known only from a search summary: **[UNVERIFIED]** by direct read).
- **Limits that lengthen the task:** LDAP filters and custom attributes do not apply to Microsoft 365 objects; management actions are unavailable for M365; M365 custom reports are users only ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html), V).

**Customer voice (anecdote level):** "custom reporting is somewhat limited" and container overflow with many custom reports, about 17 reviews in total, already recorded in [customer voice X2](manageengine-ad-customer-voice-and-security.md). Not re-researched.

**Use in the spec.** `reports-2c-builder.md` may state "ADMP documents a 10-step procedure that requires hand-written LDAP syntax for filters". It must **not** state a ManageEngine seconds figure until L-R1 is done; the activeDIQ target is an intent, not a comparison, per the comparative-claim rule.

### Lab step L-R1 (needs a licensed ADMP trial; CEO approval if it uses our identity)

Task from spec §4: one source, three filters, six columns. Fresh-install ADMP build matching the migration target (see 8043 note). Screen-record three runs by someone who knows the tool and three by someone who does not; count clicks and keystrokes from the recording; report median and range. Hand to `product-designer` for the task-time benchmark.

## 3. Storage and export of definitions (AC2)

Found:

- Bundled **PostgreSQL** (build 8043: 15.18, localhost-only, port 33306) or MS SQL Server hold ADMP configuration ([system requirements](https://www.manageengine.com/products/ad-manager/help/getting_started/system_requirements.html), V; [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf), V; via the 8043 note). That custom report definitions live in this database is an **inference**, not a documented statement: **[UNVERIFIED]**.
- Generated report **output** exports as XLSX, PDF, HTML, CSV or CSVDE via **Export as**, with description under **More > Export settings** ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html), V). Output is not the definition.
- **Sharing** to technicians at View/Edit/Full Access is in-product only and is not an export ([help](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html), V).
- A user asked how to export Scheduled List entries for import into a new ADMP environment; no answer appears in the result ([forum: Export and Import](https://pitstop.manageengine.com/portal/en/community/topic/export-and-import), F, one thread, anecdote). Unread beyond the search snippet: **[UNVERIFIED]**.
- Config changes, including custom reports, appear in the technician admin audit report (ADM-138) ([help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-admin-audit-report.html), V). This is an audit trail of change events, not a definition export.

Not found as of 2026-11-14 (absence is "not found in docs", not "does not exist"):

- Any help page describing a definition import/export file, its format, or a schema for custom reports.
- Any REST API endpoint for creating, listing or exporting custom report definitions. Community threads ask how to run a report via API with no confirmed answer in what we saw ([API for Reports](https://pitstop.manageengine.com/portal/en/community/topic/api-for-reports), F; [REST API call to run report/automation](https://pitstop.manageengine.com/portal/en/community/topic/rest-api-call-to-run-report-automation), F; snippets only). The official API doc was not read for this ticket: **[UNVERIFIED]**.
- Table and column names, and whether the raw LDAP query is stored as a plain string, a serialized object, or split into condition rows.

### Lab steps (needs a lab ADMP install; no vendor contact)

- **L-R2** Create three reports (builder-only filters; one with **Advanced Filter** raw LDAP; one with **Refine Results**). Dump the DB (`pg_dump` on the bundled instance, localhost) before and after each; diff to find the tables and columns, and see how the raw LDAP string and the Refine Results conditions are stored.
- **L-R3** Check **Copy Custom Report**, share, and any settings backup/restore in the UI for an exported file; record its format.
- **L-R4** Read the official ADMP API doc for report endpoints.
- EULA: no clause on DB access but reverse-engineering and third-party-access clauses exist ([8043 note](admp-8043-db-export-eula-findings.md) §5). Reading a customer's own DB for MIG-05 needs director/legal review before it is promised; L-R2 on our own lab install is for our research and should be cleared with the director first.

## 4. Findings that matter most

1. **No published time or click benchmark exists.** Any "N× faster" line for the builder is unsupported until L-R1 is run.
2. **Documented procedure is 10 steps and needs raw LDAP syntax for the advanced path.** That supports an intent-phrased claim only, and supports the spec's typed-builder direction.
3. **Definition storage is undocumented.** MIG-05 cannot promise automated import of ME custom definitions; plan on the customer re-entering or pasting LDAP filters, until L-R2/L-R3 show otherwise.

## 5. Open `[UNVERIFIED]` items

| Item | What verifies it |
|---|---|
| Seconds/clicks to build the §4 reference report | L-R1 |
| Definitions stored in the ADMP DB; schema; raw-query format | L-R2 |
| Any definition export/import file | L-R3 |
| REST API coverage of report definitions | L-R4 |
| Content of the 2018 LDAP-query blog (502 on fetch) | Re-fetch later |
