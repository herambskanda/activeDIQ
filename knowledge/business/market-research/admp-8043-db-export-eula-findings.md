---
title: "ADMP build 8043: database schema, table allow-list, technician-report exports, EULA"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
sources_last_checked: 2026-11-14
---

# ADMP build 8043: DB schema, table allow-list, ADM-139 exports, EULA

Answers `e2-11-migration-importer.md` §11 questions 1–2 (TM-Q28; playbook MIG-02). Ticket T-2061.
Extends [manageengine-admanager-plus.md](manageengine-admanager-plus.md); does not repeat it. Findings only.
EULA text below is a set of **facts for the director, not a legal opinion**.

Source ranks: V = vendor docs/help, P = vendor product/marketing page, F = vendor forum. Checked 2026-11-14.

## 1. Summary

| # | Question | Answer | Status |
|---|---|---|---|
| Q1a | Published DB schema for ADMP build 8043? | **Not found.** No schema or table documentation located in vendor help, KB or the security PDFs. | not found in docs as of 2026-11-14 |
| Q1b | Candidate table allow-list? | **Cannot be sourced from public material.** Only the DB name, port and engine are documented (§3). Table and column names need a lab install. | `[UNVERIFIED]`; lab step L1–L3 |
| Q1c | EULA constraints on reading the DB? | The EULA has **no clause on database access** but does bar reverse engineering, modification, distribution of third-party software, and third-party access (§5). | facts, see §5 |
| Q2 | Does ADM-139 export in every format? | **Unknown.** No page documents export formats for the technician logon report or a "technicians report". Adjacent pages list formats (§4). | `[UNVERIFIED]`; lab step L4 |

## 2. Findings that matter most

1. **No public schema exists in what we could find.** A table allow-list for MIG-02 must come from a lab install, not desk research. Do not promise "full fidelity DB read" to a partner before L1–L3 are done.
2. **The bundled DB is not reachable remotely by default.** Vendor says access is "restricted to localhost" with instance-specific credentials ([data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf), V). A read-only route therefore means either an agent/dump on the ADMP host, or the customer reconfiguring PostgreSQL (§3).
3. **Secrets are encrypted inside the DB** (AD domain credentials, technician auth tokens, M365 credentials, DB password: AES-256, same PDF). The importer must exclude those tables or columns, and should never need them.

## 3. Database facts (documented)

| Fact | Detail | Source (rank) |
|---|---|---|
| Engines | Bundled PostgreSQL, or customer MS SQL Server | [data-security PDF](https://download.manageengine.com/products/ad-manager/encryption-and-data-storage-in-admanager-plus-database.pdf) (V); fuller engine/version list already in [ADMP doc §3](manageengine-admanager-plus.md) (PostgreSQL 15.18 in 8043) |
| Bundled-DB setup-wizard values | port 33306, database `adsm`, user `admanager` (the page also lists a default password; not reproduced here) | [migration help](https://www.manageengine.com/products/ad-manager/help/migration/migrating-from-an-existing-postgresql-ms-sql-database-to-bundled-postgresql-database.html) (V). Whether these defaults survive in a hardened install is `[UNVERIFIED]` |
| Remote access | Documented only for migration: edit `pg_hba.conf` and `postgresql.conf` under `pgsql\data`. The page gives no guidance on securing or reverting this | same page (V) |
| Local-only | "Access to the built-in database is restricted to localhost" | data-security PDF (V) |
| Encrypted data | AD domain credentials, technician auth tokens, DB password, proxy settings, SSL keystore password, Microsoft 365 credentials, export results and DB backups: AES-256. Built-in technician passwords: bcrypt | data-security PDF (V) |
| Schema docs | None found. ADMP/ManageEngine forum threads asking for schemas (ManageEngine products generally) show no vendor answer ([example thread](https://pitstop.manageengine.com/portal/en/community/topic/database-schema-27-2-2017), F; product not named on the page, so weak evidence) | not found as of 2026-11-14 |
| Supported direct access | Not found in docs. Absence is documented only as "not found as of 2026-11-14", not as "unsupported" | — |

Security note (secondary): a third-party advisory describes a key exposure letting a local low-privileged user decrypt DB passwords in some ManageEngine products ([Tenable TRA-2023-35](https://ar.tenable.com/security/research/tra-2023-35), analyst/researcher). Whether ADMP build 8043 is affected is `[UNVERIFIED]`; not checked.

## 4. ADM-139 export formats

ADM-139 in the matrix is "Technician logon report and technicians report" ([help page](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/Active-Directory-Help-Desk-Technician-Logon-Report.html), V).

| Evidence | What it says | Rank |
|---|---|---|
| ADM-139 help page | Describes the logon report (host/IP, session status, duration, login/logoff times, domain, auth method; filters all / inactive / active technicians; search). **Names no export formats.** It does not describe a separate "technicians report". | V |
| [Export page](https://manageengine.com/products/ad-manager/export-active-directory-data.html) | "The lists of help desk technicians, their roles, and detailed help desk audit reports can also be exported." The page lists CSV, PDF, XLSX, HTML, CSVDE and XLS for AD data generally; it does not say which formats apply to the technician list | P |
| [Admin Audit Report help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/help-desk-admin-audit-report.html) | "Click Export As to export the generated report to CSV, PDF, XLSX, and HTML formats." This is the admin/technician **change** audit (ADM-138 area), not ADM-139 | V |
| [Technician audit log page](https://manageengine.com/products/ad-manager/technician-audit-log.html) | Archived audit reports: "PDF, HTML, XLSX and CSV". No technician or role data mentioned | P |

**Answer.** ADM-139 itself: formats **not documented**. Formats confirmed for the sibling help-desk audit report: CSV, PDF, XLSX, HTML. CSVDE and XLS appear only on marketing pages and are inconsistent across them. The spec's design (accept CSV, XLSX and HTML where present, never require one) stays correct. The vendor marketing sentence supports that a technician-and-roles list export exists, but does not name where in the UI. Do not state in any customer-facing text that a "technician inventory export" exists until L4 is done.

## 5. EULA facts

Source: [ADManager Plus licence](https://www.manageengine.com/products/ad-manager/license.html) (V). The fetched text carried no effective date or version number; whether it matches the EULA shown at install of build 8043 is `[UNVERIFIED]` (lab step L5).

| Clause (§ as quoted by the page) | Text | Relevance to DB read |
|---|---|---|
| §5 (vi) | "reverse engineer, decompile or disassemble the Licensed Software" | Reading a documented schema is not obviously this; inferring undocumented structure from the product binary would be. Legal question for counsel |
| §5 (v) | "modify or enhance the Licensed Software" | Editing `pg_hba.conf`/`postgresql.conf` is the vendor's own documented migration step, but we found no permission for other uses |
| §5 (vii) | "allow any third parties to access, use or support the Licensed Software except employees, contractors" | Applies to who may touch the install. Our staff or a partner reading the DB on the customer's behalf may fall under "contractors"; counsel to decide |
| §3 | "you will not distribute any such third party software available with the Licensed Software" | Do not redistribute or ship ADMP's bundled PostgreSQL |
| — | **No clause found on database access, access to data structures, or benchmarking** | Silence is not permission |

Practical consequence for the spec: the **customer** is the licensee, so an importer run by the customer on their own host (dump or read-only account the customer creates) is the lowest-exposure shape. An activeDIQ-operated read of a customer's ADMP DB needs counsel sign-off first. The data-security PDF's wording on "reverse engineering" refers to protecting data at rest, not licence terms.

## 6. Lab follow-ups (need an ADMP 8043 install; Evaluation edition is free for 30 days per [licensing FAQ](https://www.manageengine.com/products/ad-manager/licensing-faq.html))

Installing the trial under our identity may involve a vendor sign-up: **CEO approval required** before registering (leaving the building).

| Step | What | Output |
|---|---|---|
| L1 | Install 8043 on a Windows Server lab VM, bundled PostgreSQL; enable local `psql` with a read-only role | `\dt` table list and row counts |
| L2 | Create one of each: creation template, modification template, naming format, duplicate rule, role, technician, workflow, scheduled automation, custom report, scheduled report; diff the DB before/after | Mapping of config item to table and column (the allow-list) |
| L3 | Repeat on MS SQL Server (customers use it; HA recommends it) | Same mapping; type differences |
| L4 | Open ADM-139 reports and the technician list; record every export format offered | Per-format result, screenshots |
| L5 | Capture the EULA shown at installer time and its version/date | Dated copy for counsel |
| L6 | Confirm which tables hold secrets (§3) and that the dump route excludes them | Deny-list |

## 7. Open `[UNVERIFIED]` items

- Table and column names, and any candidate allow-list (L1–L3).
- ADM-139 export formats, and where the technician list export lives (L4).
- Whether the installed EULA matches the web copy (L5).
- Whether the documented default DB credentials persist after hardening.
- Whether TRA-2023-35 affects ADMP 8043.

Inform `product-manager`: no change to the spec's scope; §11 Q1 stays open with the lab steps above, Q2 is answered "not documented; keep the accept-any-format design".
