---
title: "ADMP custom reports: grouping, charts and task cost (ADM-097, ADM-002)"
date: 2026-11-15
updated: 2026-11-15
status: draft
owner: market-analyst
sources_last_checked: 2026-11-15
---

# ADMP custom reports: grouping, charts and task cost

Ticket T-2131, answering Q5 of `reports-eb5-grouping-charts.md` §10. Extends
[admp-custom-report-builder-task-time-and-storage.md](admp-custom-report-builder-task-time-and-storage.md)
(T-2102) and [manageengine-admanager-plus.md](manageengine-admanager-plus.md); does not repeat them.
Source ranks: V = vendor help, M = vendor marketing, F = vendor forum. Checked 2026-11-15.

## 1. Summary

| # | Question | Answer | Status |
|---|---|---|---|
| AC1 | Grouping in the custom report builder (keys, aggregations, limits) | **Not found in docs as of 2026-11-15.** The documented builder has scope, conditions, filters, columns and actions. No group-by, aggregation or limit setting appears (§2). | `[UNVERIFIED]`; lab step L-G1 |
| AC2 | Charts on a grouped result; types; how attached | No chart setting is documented in the custom report builder. Charts are documented for **dashboard widgets**, where a report is added with "Add To Dashboard" and the chart type switches between **bar and column** only (§3). | Builder-level chart `[UNVERIFIED]`; lab step L-G2 |
| AC3 | Clicks/seconds to build a grouped and charted report | **Cannot be measured as a single task**, because no grouping step is documented. The nearest documented path is the 10-step build (T-2102) plus a dashboard step (§4). | seconds `[UNVERIFIED]`; lab step L-G3 |

## 2. Grouping (AC1)

Read in full on 2026-11-15:

- [ADMP help, Custom Reports](https://www.manageengine.com/products/ad-manager/help/reports/viewing-active-directory-custom-reports.html) (V). Describes column selection, filters, Refine Results, management actions and export (XLSX, PDF, HTML, CSV, CSVDE). It has **no mention** of group-by, aggregation, sorting or row limits.
- [Custom reports guide](https://www.manageengine.com/products/ad-manager/custom-reports-for-active-directory.html) (M). No mention of group-by, charts, graphs, aggregation or pivot. The only "grouping" in it is *grouped filter conditions*: "add grouped conditions which is applicable to both LDAP Filters as well as Refine Results". That nests filter logic. It does not summarise output, so it must not be read as report grouping.

Two web searches (2026-11-15) for ADMP custom-report group-by and chart terms returned only the pages above, forum threads and blog posts, none describing grouping.

**What this supports.** "Grouping or aggregation in the ADMP custom report builder: not found in docs as of 2026-11-15." It does **not** support "ADMP cannot group". Canned reports may group or count (not checked here). Customers may export to a spreadsheet and pivot there (an inference, `[UNVERIFIED]`).

## 3. Charts (AC2)

Source: [ADMP help, dashboard view](https://www.manageengine.com/products/ad-manager/help/introduction/active-directory-dashboard-view.html) (V, fetched 2026-11-15).

- Chart type can be switched "from bar type to column type and vice-versa" through the widget's edit icon. **No other chart type (pie, line) is named on that page.**
- Attaching: run a report, apply any OU filters or inputs, click **Add To Dashboard**, then pick or create a tab and widget, name it and save. Widgets can also be added from a predefined list of AD report widgets.
- The page **does not say** whether a user-built custom report can be added this way. That is `[UNVERIFIED]` (L-G2). It also does not say whether a widget can show a grouped breakdown.
- Forum evidence of pie charts and a total-on-pie request exists ([Total in pie charts](https://pitstop.manageengine.com/portal/en/community/topic/total-in-pie-charts), F), but the search summary did not show which product or an answer. **Unread, `[UNVERIFIED]`**, not used as a claim.
- ADAudit Plus has a documented chart-in-export option ([KB, ADAudit Plus](https://pitstop.manageengine.com/portal/en/kb/articles/how-to-enable-the-chart-option-when-exporting-reports-in-adaudit-plus-4-8-2025), F). It is a different product and says nothing about ADMP.

## 4. Task cost (AC3)

No grouped-and-charted task exists in the documentation to count, and no timing was published (see T-2102 §2). The nearest documented route is: the 10-step custom-report build (T-2102 §2), then run the report and **Add To Dashboard** (about 4 further steps: tab, widget, name, save). That 14-step figure is a **step count assembled from two help pages**, not a measured click count, and it assumes the second step works for custom reports (unverified).

### Lab steps (licensed ADMP trial; CEO approval if our identity is used; no vendor contact)

- **L-G1** In the custom report builder, look for any group-by, count, sort or limit control on every tab. Screenshot each tab. Also run a canned report with a count to see how ADMP presents counts.
- **L-G2** Run a custom report, look for a chart or graph control in the result, and try **Add To Dashboard**. Record chart types offered and whether it works for custom reports.
- **L-G3** Task: group users by department, count each, show a chart. Screen-record three runs by an expert and three by a newcomer; count clicks and keystrokes; report median and range. Hand to `product-designer`. If L-G1 finds no grouping, record the nearest workaround (export, pivot) and its clicks instead.

## 5. Findings that matter most

1. **No documented grouping or aggregation in ADMP's custom report builder.** Parity claim for grouping stays unmade; the spec may say "not found in ADMP docs as of 2026-11-15", not "ADMP lacks grouping".
2. **Charts are documented only on dashboard widgets, bar and column only.** Any "more chart types" line is an intent statement until L-G2, and also depends on what the spec ships.
3. **No time or click benchmark is possible yet.** Do not publish an "N× faster" claim for grouped, charted reports. Use intent wording ("one builder, one step") only for what we ship.

## 6. Use in the spec

`reports-eb5-grouping-charts.md` §1 and §2 may replace "unknown `[UNVERIFIED]`" with the wording in finding 1 and cite this note. The targets stay absolute. Suggest `product-manager` keep ADM-097 and ADM-002 as the parity rows; this note adds no new feature IDs.

## 7. Open `[UNVERIFIED]` items

| Item | What verifies it |
|---|---|
| Any group-by, aggregation or limit in the builder | L-G1 |
| Charts on custom report results; types; custom reports as widgets | L-G2 |
| Seconds/clicks for a grouped and charted report | L-G3 |
| Pie-chart threads (product and answer unread) | Read the threads |
