---
title: Glossary
updated: 2026-10-02
budget: 120 lines
---

# Glossary

## Active Directory and identity
- **AD DS** — Active Directory Domain Services. **DC** — domain controller. **GC** — Global Catalog (partial replica of every domain in the forest).
- **Forest / domain / trust** — security boundary / replication & admin boundary / authentication path between domains.
- **OU** — organisational unit (container for delegation and GPO linking). **DN / RDN** — distinguished name / relative DN.
- **GPO** — Group Policy Object (AD object + SYSVOL files). **SYSVOL** — replicated share holding policies and scripts.
- **SID / objectGUID** — security identifier / immutable object identity (binary attributes).
- **UAC (userAccountControl)** — bit flags for account state (disabled, password never expires, …).
- **lastLogon vs lastLogonTimestamp** — per-DC, non-replicated vs replicated with ~9–14 day lag.
- **LDAP / LDAPS** — directory protocol / LDAP over TLS (636). **Signing & channel binding** — required hardening.
- **Kerberos, KDC, TGT, SPN** — ticket-based authentication; Kerberoasting abuses SPNs. **NTLM** — legacy challenge-response auth.
- **gMSA** — group managed service account (auto-rotated password). **LAPS** — local admin password solution.
- **Tiering (Tier 0/1/2)** — admin model; Tier 0 = identity control plane (DCs, AD, anything that can control them).
- **DirSync / uSNChanged** — change-tracking mechanisms. **Tombstone / AD Recycle Bin** — deleted-object lifecycle and recovery.
- **FSMO** — single-master operation roles. **AdminSDHolder** — template ACL protecting privileged accounts.
- **Entra ID** — Microsoft's cloud directory (formerly Azure AD). **Entra Connect / Cloud Sync** — hybrid sync. **Microsoft Graph** — API for Entra/M365.
- **SSPR** — self-service password reset. **MFA** — multi-factor authentication. **SSO** — single sign-on (SAML, OIDC, WS-Fed).
- **RADIUS** — protocol used for VPN MFA. **Credential provider** — Windows logon-screen plug-in (C++/COM, runs in LogonUI).
- **Password filter** — DLL loaded by LSASS on DCs to enforce or sync passwords (crash = DC outage).
- **ITDR** — identity threat detection & response. **ISPM** — identity security posture management.
- **JML** — joiner/mover/leaver lifecycle. **RBAC / delegation** — role-based access / scoped admin rights.

## ManageEngine
- **ADManager Plus (ADMP)** — management, reporting, automation, workflow, delegation. Parity IDs `ADM-`.
- **ADAudit Plus (ADAP)** — change auditing, logon auditing, file auditing, threat detection. `ADA-`.
- **ADSelfService Plus (ADSSP)** — SSPR, MFA, SSO, password sync. `ADSS-`.
- **RecoveryManager Plus** — AD/M365 backup and recovery. `RMP-`. **M365 Manager Plus** — `M365-`. **Exchange Reporter Plus** — `ERP-`.
- **AD360** — the suite bundling the above. `AD360-`. **Identity360** — ManageEngine's cloud identity platform.
- **Help desk technician** — a delegated operator; a ManageEngine licensing unit.

## Factory
- **CEO** — heramb; answers directional questions only. **Director** — `factory-director`, runs the floor and is the CEO's session.
- **Ticket / stage / flow** — unit of work / its current step / the ordered stages for its type.
- **Decision kinds** — `directional` (CEO must answer), `advisory` (default applies after 72 h), `notice` (factory decided; CEO may veto).
- **Action item** — something only the CEO can do (access, money, introductions).
- **Run** — one headless worker session on one ticket stage. **Dispatcher** — the deterministic loop that launches runs.
- **Handoff / checkpoint** — the note a session leaves at a context checkpoint so a fresh session can continue.
- **Fitness function** — an automated CI check that an architectural decision still holds.
