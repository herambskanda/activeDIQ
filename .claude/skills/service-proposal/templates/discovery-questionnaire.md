---
title: "Discovery questionnaire — moving from ManageEngine to activeDIQ"
version: 1
status: draft          # the generic version is approved by the CEO once, then reused
---

<!-- Answers are stored as knowledge/business/partnerships/<partner-slug>/discovery.md with the
same numbering, each answer dated and attributed to its source. Unknown → [TODO]. -->

# Discovery questionnaire

Thank you for taking the time. These questions help us plan a move that is safe for your users
and your audit obligations. Approximate answers are fine; "don't know" is a useful answer.

## A. ManageEngine today

1. Which ManageEngine products do you run? (ADManager Plus, ADAudit Plus, ADSelfService Plus,
   AD360, RecoveryManager Plus, M365 Manager Plus, Exchange Reporter Plus, other)
2. For each: edition (Standard / Professional / other), build number, licence unit and count
   (domains, technicians, users, servers, workstations), and add-ons.
3. Renewal date for each licence, and notice period.
4. Where each runs (servers, OS, database: bundled PostgreSQL or external SQL Server), and any
   high-availability or distributed components.
5. Who administers ManageEngine, and how much time it takes them per month.

## B. Directory environment

6. Forests and domains (count, functional levels), trusts.
7. Object counts: users, groups, computers, OUs, contacts; largest group's member count.
8. Domain controllers: count, Windows Server versions, sites.
9. Microsoft Entra ID: tenant(s), sync method (Entra Connect / Cloud Sync), synced vs cloud-only
   users, Exchange on-prem / Exchange Online / hybrid.
10. Is the AD Recycle Bin enabled? Any fine-grained password policies?

## C. Workflows and delegation

11. Your top 10 recurring admin tasks in ManageEngine (joiner, mover, leaver, bulk updates,
    group requests…) with rough monthly volume.
12. User-creation templates: how many, and what they set.
13. Workflows and approvals in use (request → approve → execute): which, and who approves.
14. Delegation model: help-desk technician roles, their permissions and OU scopes; how many
    technicians.
15. Automations and scheduled tasks (cleanups, inactive-account disabling, HR-driven
    provisioning — from which HR system?).

## D. Reports and audit

16. Reports you rely on (name them), who receives them, how often, in which format.
17. Audit: what you alert on (privileged groups, GPO changes, lockouts, file servers?), where
    alerts go (email, SIEM — which?).
18. Audit-retention requirements: how long, which regulation or policy (e.g. SOX, PCI DSS,
    DORA, NIS2, local regulator), and where archives are kept today.
19. Upcoming audits or certification dates.

## E. Self-service and MFA

20. Users enrolled for self-service password reset, out of total; enrollment methods used.
21. Monthly self-service resets and unlocks; help-desk password tickets per month.
22. MFA in ADSelfService Plus: for which logons (Windows, macOS, Linux, VPN, OWA, RDP) and which
    authenticators; number of machines with the logon agent.
23. Password policy enforcement or password sync to other systems in use?

## F. Integrations

24. Integrations with ManageEngine today: ITSM (ServiceNow, ServiceDesk Plus, Jira…), SIEM,
    HR, email, SMS gateway, REST API or scripts calling ManageEngine.
25. PowerShell or scripts your team runs alongside ManageEngine.

## G. Pain points and goals

26. What works well in ManageEngine that we must not make worse?
27. What frustrates your admins, help desk, auditors or end users today?
28. What would make this move a success for you in six months? How would you measure it?
29. Constraints: change freezes, maintenance windows, security approval process for new
    tools on domain controllers, data-residency requirements.
30. Who decides, who else is involved, and your timeline.
