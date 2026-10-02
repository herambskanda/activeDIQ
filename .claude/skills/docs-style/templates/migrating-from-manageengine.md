---
title: Migrating from ManageEngine <ADManager Plus | ADAudit Plus | ADSelfService Plus>
kind: how-to            # one page per ManageEngine product, plus an explanation overview page
audience: admin
applies_to: ">=<version>"
verified_on: <version or sha> YYYY-MM-DD
sources_last_checked: YYYY-MM-DD
---

<!-- Rules: every statement about ManageEngine is factual, sourced (inline URL to ManageEngine's
own docs where possible), dated, and never disparaging (competitive-intel §4). Anything not yet
verified is [TODO] and blocks publishing. Mapping rows come from the parity matrix by feature
ID; keep the IDs in HTML comments. The phases match the service migration plan
(service-proposal skill) so services and docs tell the same story. -->

# Migrating from ManageEngine <product>

This guide moves your <product> configuration to activeDIQ with a parallel run, so you can
compare results before you switch. Typical duration: <from the migration playbook, or omit>.

## How concepts map

| In <product> | In activeDIQ | Notes |
| --- | --- | --- |
| <Help desk technician + delegation> | <Role + scope> | <!-- ADM-… --> |
| <User creation template> | <Template> | |
| <Scheduled report> | <Scheduled report> | |
| <Alert profile> (ADAudit Plus) | <Alert rule> | |
| <Self-service policy> (ADSelfService Plus) | <Policy> | |
| <Feature with no equivalent yet> | Not yet available — <workaround> | Say so plainly |

## Before you start

- Versions supported as a source: <product build range> `[TODO]`.
- Export rights in <product>: <role needed> (source).
- activeDIQ installed and connected to the same domains ([Connect a domain](../../admin/how-to/connect-a-domain.md)).

## 1. Take inventory

<What to export from <product> and how (menu paths cited from ManageEngine docs), and what the
activeDIQ inventory report shows.>

## 2. Map and import

<Import steps; what is imported automatically, what is recreated by hand, how to review the
mapping report.>

## 3. Run both in parallel

<What to run in parallel and for how long; how to compare (report diff, audit comparison).
What must NOT run in both at once — e.g. two password-policy enforcers or two self-service
portals for the same users — and how to avoid it.>

## 4. Cut over

<Ordered steps: switch end users (portal URL, logon-screen agent), switch admins, disable
<product> jobs, keep <product> audit data available for its retention period.>

## 5. After cutover

<Hypercare checks; decommissioning <product> agents and service accounts; what to keep for
compliance (audit archives) and for how long.>

## Audit history and retention

<How existing <product> audit data stays available to meet retention obligations (archive,
read-only instance, export) — [TODO] until verified.>
