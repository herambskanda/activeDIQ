---
title: "Architecture at a glance"
date: 2026-10-09
updated: 2026-10-09
status: review
owner: heramb
author: factory-director
binding_sources: blueprint v0 (review), ADR-0001, ADR-0002, ADR-0003, ADR-0005 (ratified)
---

# Architecture at a glance

**[Open the interactive diagram](diagrams/architecture.html)** (new tab). Click any box for what it
does, where its code lives and who owns it. Tabs cover the import rules, one write step by step,
the three deployment profiles and the repository map. It uses the board's theme and follows your
light or dark setting.

This page is the short version of the [full blueprint](blueprint.md). Where the blueprint and a
ratified ADR disagree, the ADR wins.

## The three ideas

- **The public API is the product boundary.** Everything a human or script does is an OpenAPI
  operation. The web console is one client and has no private endpoints.
- **The connector is the only path to a directory.** Directory credentials exist only inside it, and
  it reaches a directory only through typed operations.
- **Modules plug into the kernel, never the reverse.** The platform kernel imports nothing above it,
  so it can be extracted and shared with UEM later.

## The system on one page

```
  Admins / help desk (browser)     Integrations (ServiceNow, SDP, scripts)    End users [M4]
            | HTTPS                          | HTTPS + API token                  | HTTPS
            v                                v                                    v
+--------------------------- server process  (cmd/server) ---------------------+  +-- edge [M4] --+
|  apihost: HTTP, authn, strict JSON, problem types, embedded web UI           |<-| stateless,    |
|  +-------------- feature modules  internal/modules/<id>/ ------------------+ |  | no secrets    |
|  | connections objects helpdesk delegation lifecycle workflow reports ...   | |  +---------------+
|  +------v------- directory domain ---------+  +------v------ platform kernel ------+
|  | ldapfilter dn attr model inventory sync |  | tenant authn authz audit jobs ...  |
|  +--------------------|--------------------+  +------------------------------------+
|  +--------------------v-- connector  internal/connector/ -------------------------+
|  | providers: ad (ldap, kerberos) | entra (graph) | credential custody            |
+--------|------------------------------|--------------^-------------^-------------+
         | LDAPS / Kerberos + CBT       | HTTPS Graph  | gRPC mTLS   | SQL
         v                              v              | (dial-in)   v
  Domain controllers             Microsoft Entra ID    |      PostgreSQL + blob store
                                 remote connector / host agent [M3] dial out to the server
```

## Where to read next

- [Blueprint v0](blueprint.md): every component, the import matrix, the job and audit pipelines.
- [Threat model](threat-model.md) and [safe primitives](safe-primitives.md): why the connector is the only path.
- [Module pages](modules/README.md): one page per feature module.
- ADRs in `knowledge/development/decisions/`: stack, deployment, module system, API contract, operation pipeline.
