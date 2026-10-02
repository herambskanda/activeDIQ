---
title: Partner Discovery Questionnaire (ManageEngine AD estates)
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Partner Discovery Questionnaire

**How to use this file**
- **Part A** is the partner-facing questionnaire: 40 questions in 10 groups. Copy Part A only.
  Sending it is an outward-facing action, so it needs CEO approval first (`ceo-decisions`,
  category 6).
- **Part B** is the internal "why we ask" key, one line per question, with the artifact each
  answer feeds. **Never send Part B.**
- Answers feed Phase 0 (Discovery) of the
  [migration playbook](../service/manageengine-migration-playbook.md) and the scope sheet for a
  [pilot](../service/pilot-offer-outline.md).
- Partner names and answers are stored only under `knowledge/business/partnerships/`
  (CLAUDE.md rule 8).
- Part A deliberately makes no claims about ManageEngine or about activeDIQ. It only asks
  questions [CV §6.3].

Source key for Part B:
[ADMP](../market-research/manageengine-admanager-plus.md) ·
[ADAP](../market-research/manageengine-adaudit-plus.md) ·
[ADSSP](../market-research/manageengine-adselfservice-plus.md) ·
[AD360C](../market-research/manageengine-ad360-suite-and-commercials.md) ·
[CV](../market-research/manageengine-ad-customer-voice-and-security.md) ·
[LAND](../competitive-analysis/ad-management-market-landscape.md) ·
[FEAS](../../development/architecture/build-feasibility/ad-technical-feasibility.md) ·
[playbook](../service/manageengine-migration-playbook.md)

---

## Part A: Partner-facing questionnaire

> **Thank you for helping us understand your environment.** Approximate answers are fine. Skip
> anything you'd rather discuss live. Please don't include passwords, personal data or
> confidential configuration exports in your replies; we'll arrange a secure channel if
> samples are needed.

### 1. Environment and scale
1. How many AD forests and domains (including child domains) do you run, with how many domain
   controllers, on which Windows Server versions, across how many sites?
2. Roughly how many enabled user accounts, computers, groups and service accounts do you have?
3. Do you use Microsoft Entra ID / Microsoft 365? If so: how many tenants, which sync tool
   (Entra Connect Sync or Cloud Sync), which Entra ID licence tier, and do you still run
   Exchange on-premises? Do you use Google Workspace?
4. What is your endpoint mix (Windows / macOS / Linux), and what share of staff work remotely
   or over VPN?

### 2. ManageEngine products, editions, licences and renewals
5. Which ManageEngine products do you run today (ADManager Plus, ADAudit Plus, ADSelfService
   Plus, AD360, RecoveryManager Plus, M365 Manager Plus, Exchange Reporter Plus, Log360,
   ServiceDesk Plus, Endpoint Central, PAM360, other)? For each: edition and build number.
6. For each product, what are your licence quantities and add-ons? (For example: domains and
   technicians; DCs, servers, file servers, workstations and tenants audited; self-service users
   and Endpoint MFA; backup users.)
7. Is each product on subscription or perpetual with maintenance, and when is each renewal or
   maintenance date?
8. How is each product hosted: number of servers or VMs, database (bundled PostgreSQL or
   Microsoft SQL Server), high availability, internet-facing components?
9. Who looks after these products, roughly how many hours a month go into upkeep and upgrades,
   and when did you last upgrade each one?

### 3. Features used daily
10. What are the ten tasks your team performs most often in your AD tooling (e.g. create user,
    reset password, unlock, group changes, offboarding)? Approximate weekly volumes help.
11. Do you run bulk operations from CSV files? From which sources (HR, scripts, manual), how
    often, and could you share a header row with no personal data?
12. Roughly how many user-creation templates, naming formats and OU-placement rules do you
    maintain?
13. Which Microsoft 365 / Exchange tasks do you perform from your AD tooling (licences,
    mailboxes, groups, shared mailboxes)?

### 4. Workflows and delegation
14. How many technicians or help-desk staff use the tools, and how are their roles scoped (by
    OU, by group, by domain, group-based delegation)?
15. Is any technician login used by more than one person?
16. How many approval workflows do you run, who approves, are there SLAs or escalations, and
    are requests raised from an ITSM tool?
17. Which automations do you rely on (scheduled cleanup, leaver processing, HR-driven
    provisioning, event-triggered actions), and do any of them run custom scripts?

### 5. Reports and compliance
18. Which regulations or frameworks do you report against (e.g. SOX, HIPAA, PCI DSS, GDPR,
    ISO 27001, DORA, NIS2, RBI/SEBI, CERT-In)?
19. How many scheduled reports do you send, to whom (including external auditors), and in which
    formats?
20. How many custom reports do you maintain, and which ten reports do your auditors ask for by
    name?
21. Do you run access reviews or certifications today? How often, and who completes them?

### 6. Auditing and retention
22. What do you audit today: AD changes, logons, lockouts, Windows file servers, NAS (which
    vendors), member servers, workstations, Entra ID / Microsoft 365?
23. What is your audit-log retention policy (online vs archived), how much audit data do you
    hold, how far back must you be able to search, and are any legal holds in place?
24. Is collection agent-based or agentless, and did your auditing tool create or change your
    audit-policy GPOs?
25. How many custom alert profiles do you use, who receives alerts, do alerts create tickets,
    and do you forward events to a SIEM (which one, which format)?

### 7. Self-service password reset and MFA
26. How many users are enrolled for self-service, and roughly what share of all users is that?
27. Which authentication methods are enabled (e.g. security questions, email/SMS codes,
    authenticator apps, push, FIDO2/passkeys, YubiKey, Duo, RSA, RADIUS, smart card, Entra
    MFA), and roughly what share of users uses each?
28. Where is MFA enforced: Windows / macOS / Linux logon, RDP, UAC, VPN (which VPN, RADIUS via
    Windows NPS?), OWA, single sign-on apps (how many)?
29. On how many endpoints is the logon-screen agent deployed, and which tool deploys it (GPO,
    SCCM, Intune, Endpoint Central, other)?
30. Do you use password-policy enforcement, a breached-password check, password expiry
    notifications or password synchronization to other systems? Which targets?

### 8. Integrations
31. Which ITSM tool and which HR systems are connected to your AD tooling?
32. Which SIEM / SOAR, dashboards (e.g. Power BI) or in-house scripts consume data from, or call
    the APIs of, your current tools?
33. Which other identity or security tools sit around AD (PAM, IGA, Okta / Entra MFA, AD
    backup or recovery, identity threat detection)?

### 9. Pain points and wishes
34. What are the three things that slow your team down most in day-to-day AD administration?
35. If you could change three things about your current AD tooling, what would they be?
36. What would a replacement absolutely have to do on day one, and what would make a switch
    not worth it for you?

### 10. Constraints: hosting, security, procurement
37. Which deployment models are acceptable: vendor-hosted SaaS with an outbound-only connector
    on-site, self-hosted (Windows or Linux), air-gapped? Any data-residency requirements?
38. What does your security review of a new vendor involve (questionnaires, SOC 2 / ISO 27001,
    penetration-test report, architecture review)? Would an agent or a password-filter
    component on domain controllers be acceptable?
39. How do you buy software of this kind (direct or reseller, budget cycle, approval steps,
    typical lead time, preferred contract term)?
40. Would you consider a pilot? If so, who would take part, is a test or scoped production
    environment available, and which time window suits you?

---

## Part B: Internal "why we ask" key (do not send)

| Q | Why we ask (one line) | Feeds |
|---|---|---|
| 1 | ADMP licenses every child domain separately [ADMP §1.5 #1]; DC OS sets our support floor (WS2016+ question) [FEAS App. A #1] | Scope sheet; pricing; feasibility |
| 2 | We plan to meter enabled human identities only [AD360C §8.1]; sizes the pilot and import volume | Pricing (CEO); MIG-01 sizing |
| 3 | Most targets are hybrid; Entra licence tier limits audit depth [ADAP §1.6 #6]; Connect Sync must upgrade by 7 Apr 2027 [LAND §7.1 #6] | Scope; hybrid health-check door-opener |
| 4 | Decides whether macOS/Linux logon agents (Phase 3 [FEAS §6.3]) and cached-credential/VPN flows [ADSS-009, 010] are needed | ADSSP migration timing |
| 5 | Shows which ManageEngine products and builds we replace and which suite ties hold them [CV §5.2]; build numbers drive importer versions | MIG-02 adapters; wave plan |
| 6 | Licence counts show their real spend and the add-ons we must cover in-tier [AD360C §6.6, §8.1] | TCO comparison; packaging |
| 7 | Renewal and maintenance dates are the switching window [CV §5.4]; the cutover must land before them [playbook R7] | Timeline; co-term decision (CEO) |
| 8 | Hidden TCO (hosts, SQL, HA) [AD360C §6.7]; database type decides the import route [playbook §4] | TCO; MIG-02 |
| 9 | Upgrade effort is a top complaint (≈16 reviews) [CV §2.2 X3]; quantifies our "upgrades that just happen" wedge [CV §6.1 #1] | ROI case |
| 10 | The top tasks become the timed task benchmark against ADMP [CV §6.2; LAND §6] | Pilot success criteria |
| 11 | ADMP CSV needs LDAP headers and DN syntax [ADM-011]; we must accept their existing files unchanged | MIG-04 |
| 12 | Templates and naming formats are sunk configuration [CV §5.2]; counts size the rebuild effort | MIG-02 effort estimate |
| 13 | M365 provisioning is a day-one ADMP expectation [ADMP §7a]; Exchange Online sits in our Phase 3 [FEAS §6.3] | Scope gap check |
| 14 | Delegation is a core reason ADMP is bought [ADMP §7a]; scoping model maps to our roles | MIG-02 roles |
| 15 | Per-technician pricing leads some customers to share admin accounts [CV §5.3]; asked neutrally | MIG-16; security narrative |
| 16 | Workflows (ADM-116–123) have no documented export [ADMP §2.7]; ITSM-driven requests need our connectors | MIG-02; integration scope |
| 17 | Automations carry the double-execution risk [playbook R2]; custom scripts must be rewritten [CV §5.3] | MIG-10, MIG-14 |
| 18 | Canned compliance reports are what keeps customers [CV Key takeaways #2]; DORA/NIS2 are possible leapfrogs [ADAP §7c #8] | Report parity pack (MIG-05) |
| 19 | Recipients (auditors) notice any change [playbook R3] | MIG-06 |
| 20 | Custom-report limits are the #2 complaint (≈17) [CV §2.2 X2]; auditor-known report names must carry over [ADAP §7a] | MIG-05 |
| 21 | Six-monthly access reviews are a regulatory checkbox [LAND Key findings #6]; GRC is a paid ADMP add-on [ADMP W14] | Upsell / tier fit |
| 22 | Audit scope decides ADAP parity work, especially NAS vendors [ADAP §7a] | Scope; feasibility |
| 23 | Audit-history retention is a top switching barrier [CV §5.2]; picks the history-bridge option [ADAP §7a] | MIG-07 |
| 24 | We should reuse their audit policy rather than re-push it [ADAP §7a option 6]; agents vs agentless affects the swap kit | MIG-08, MIG-11 |
| 25 | Alert noise is a known pain [CV §2.2 X11]; SIEM parsers must keep working [ADAP §7a] | MIG-02; SIEM field mapping |
| 26 | Re-enrollment is the decisive end-user switching cost [ADSSP §0 #6] | MIG-09 sizing |
| 27 | Roughly half the enrollment surface migrates with zero user effort, depending on methods [ADSSP §8a] | Re-enrollment plan; authenticator priority |
| 28 | Endpoint and VPN MFA need the credential provider and RADIUS (Phase 2) [FEAS §6.3]; NPS dependency [ADSSP W11] | ADSSP wave timing |
| 29 | Agent replacement goes through their existing deployment tool [ADSS-132] | MIG-11 |
| 30 | Password filter is a long pole needing Microsoft LSA signing [FEAS §0, §1.7] | Scope; timing |
| 31 | ServiceNow and HR connectors must exist before an ITSM- or HR-driven customer can cut over [playbook §4.1] | Integration backlog |
| 32 | Hidden API consumers break silently [playbook R9]; ADMP's API quota is 50 successful calls per technician per day [ADM-190], and integrations near that limit favor our unmetered-API wedge [ADMP §7c] | MIG-17 evaluation; API positioning |
| 33 | Shows overlap and budget neighbors; recovery and ITDR are adjacent [LAND §4.8, §7.2] | Positioning |
| 34 | Tests our UX thesis against their words; the UI is the #1 complaint (≈28) [CV §2.2 X1] | Pilot success criteria; demo script |
| 35 | Surfaces leapfrog priorities (preview/undo, report builder, unified console) [ADMP §7c] | Roadmap input |
| 36 | Defines the must-have list and deal-breakers for the scope sheet | Scope sheet; go/no-go |
| 37 | SaaS acceptance and data residency are open questions [FEAS App. A #5]; deployment profiles [FEAS §4.3] | Deployment ADR input |
| 38 | Enterprise buyers will run a security review of us [CV §5.4]; DC agent acceptance is open [FEAS App. A #2] | Security pack; architecture |
| 39 | Sets the sales-cycle timeline and contract shape [CV §5.4] | Forecast; pilot timing |
| 40 | Qualifies the partner for a pilot and the people and environment we need | [pilot-offer-outline.md](../service/pilot-offer-outline.md) |
