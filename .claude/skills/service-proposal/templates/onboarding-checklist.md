---
title: "Onboarding: <partner-slug>"
date: YYYY-MM-DD
status: active
author: service-manager
partner: <partner-slug>
sow: knowledge/business/partnerships/<partner-slug>/sow.md
---

<!-- Lives at knowledge/business/partnerships/<partner-slug>/onboarding.md. Tick items with the
date and evidence (doc path, ticket). Each technical step follows an SOP from
knowledge/business/service/sops/ — rehearsed, per the sop-writing skill. -->

# Onboarding — <partner-slug>

## 1. Kick-off (week 0)

- [ ] SOW signed (CEO confirmed) — date:
- [ ] Contacts exchanged: project lead, AD owner, security approver, help-desk lead
- [ ] Success measures from discovery G28 restated and agreed
- [ ] Communication cadence (weekly status; channel for Severity 1)
- [ ] ManageEngine renewal date and notice period confirmed; plan timed against it

## 2. Access and security approval

- [ ] Customer security review of activeDIQ completed (security pack: architecture, rights
      required, data flows, hardening guide)
- [ ] Service accounts / gMSA created with **least-privilege rights** from the proposal §3 — no
      Domain Admin for run-time accounts
- [ ] Network paths: activeDIQ server → DCs (LDAPS 636, Kerberos, and any agent ports from
      the install guide); certificates trusted
- [ ] Change approvals for anything installed on DCs or endpoints

## 3. Install and connect

- [ ] Server installed per the install SOP; version recorded:
- [ ] Domains connected read-only first; object counts match discovery B7 within tolerance
- [ ] Console sign-in with MFA for all admins; default credentials impossible / changed
- [ ] Backups of activeDIQ configuration and database scheduled and a restore tested

## 4. Configure

- [ ] Roles and scopes mapped from ManageEngine delegation (mapping report D1)
- [ ] Templates, workflows, scheduled reports, alert rules recreated or imported
- [ ] Self-service policies and enrollment plan (if in scope)
- [ ] Integrations: ITSM, SIEM, email/SMS as in discovery F24

## 5. Parallel run

- [ ] One-owner table agreed (password policy, self-service portal, audit-policy GPO)
- [ ] Comparison checks scheduled (reports, audit events) and results logged daily
- [ ] Exit criteria met — date:

## 6. Train

- [ ] Admins: <n> session(s) — attendance:
- [ ] Help desk: <n> session(s)
- [ ] Auditors: report and evidence walkthrough
- [ ] End-user communications sent (if self-service in scope)

## 7. Cutover and hypercare

- [ ] Pilot group live; issues triaged
- [ ] Waves complete; rollback window closed
- [ ] ManageEngine jobs disabled; audit history retention arrangement in place
- [ ] Hypercare exit: no open S1/S2; ticket volume at baseline for <n> days
- [ ] ManageEngine agents and service accounts decommissioned (customer action, verified)

## 8. Close

- [ ] Handover to support tier per SLA; customer has portal access and escalation path
- [ ] Lessons learned → `knowledge/memory/lessons.md` (generic only; no partner names) and the
      migration playbook in `knowledge/business/service/`
- [ ] First quarterly review scheduled
