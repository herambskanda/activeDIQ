---
title: "Decision prep: published API deprecation and support window (ADR-0004 rule 7)"
date: 2026-10-21
updated: 2026-10-21
status: draft
owner: heramb
author: product-manager
ticket: T-0036
epic: E-001
milestone: M1
---

# Decision prep: how long we promise to keep a deprecated API operation

**For:** factory-director, to take to the CEO as one `directional` decision (it is a published commitment, so it leaves the building).
**Blocks:** GA release checklist and the published API policy. Does **not** block M1 build, because ADR-0004 already enforces `deprecated` + `x-activediq-sunset` + `Deprecation`/`Sunset` headers whatever the number is.

## The question

When we deprecate a `stable` API operation, how long do we promise customers it keeps working?

## Context

- ADR-0004 rule 7 proposes "at least two minor releases **and** at least 12 months, whichever is longer", and leaves the promise to the CEO ([ADR-0004](../../development/decisions/0004-public-api-contract-openapi-first.md)).
- The promise covers only `stable` operations. `preview` operations may change at any time and carry no window.
- Security or reliability emergencies are the one exception any option must keep. Microsoft keeps the same carve-out ([Microsoft Graph versioning](https://learn.microsoft.com/en-us/graph/versioning-and-support)).
- Customers script against this API (PowerShell, scheduled jobs, ITSM glue). Sunsetting under them is the migration pain we are selling against.

## Competitor evidence

| Source | What it shows |
| --- | --- |
| ManageEngine ADManager Plus | We found **no published deprecation or support-window policy** for its REST API (searched; nothing surfaced). Observed behaviour: the older Generate Authtoken API has been deprecated since January 2025 ([research, release notes](../../business/market-research/manageengine-admanager-plus.md)). Parity rows ADM-188 and ADM-189 cover its two API versions. A published window is therefore an enhancement over ManageEngine, not parity. |
| ManageEngine, sister product (ServiceDesk Plus Cloud) | V1 REST API retirement was announced with a cutoff of 31 Aug 2024 and 404 afterwards ([ManageEngine community notice](https://pitstop.manageengine.com/portal/en/community/topic/deprecating-support-for-v1-rest-apis-for-servicedesk-plus-cloud)). It shows the vendor does hard cutoffs. The notice period is not stated in what we read `[UNVERIFIED]`. |
| Microsoft Graph (the API our Entra customers already live with) | Deprecated at least **24 months** before retirement for v1.0 and GA APIs. Security and reliability exceptions are allowed. The `beta` endpoint can break at any time ([Microsoft Learn](https://learn.microsoft.com/en-us/graph/versioning-and-support)). |

Open item: we have no sourced data on Okta, Stripe or similar identity vendors. Not needed to decide. If the CEO wants it, file a `research` ticket for `market-analyst`.

## Options

| | Window for a `stable` operation | Buys | Honestly costs |
| --- | --- | --- | --- |
| **a (recommended)** | **At least 12 months and at least two minor releases, whichever is longer** (the ADR-0004 default) | Beats ManageEngine, which publishes nothing. Long enough for a yearly script review cycle. Cheap to keep: we carry old operations next to new ones in one `/api/v1`. | Below Microsoft's 24 months. An Entra-heavy buyer may compare us to Graph. The real window depends on a release cadence not yet set. |
| **b** | **At least 24 months and at least two minor releases**, matching Microsoft Graph | Strongest trust signal for regulated and slow-change enterprises. Matches a vendor customers already know. | We maintain deprecated operations (and their tests and security fixes) twice as long. Hurts early on, when we will most want to fix API mistakes. A promise this long is hard to retract. |
| **c** | **Publish no number at GA**; promise only a minimum notice (6 months) and the headers, then revisit after the first year | Keeps freedom while the API is young. Nothing to retract. | A non-answer next to Graph's 24 months. Weak against the "scripts break on upgrade" objection. The ADR-0004 release gate would still need a number to check against. |

## Recommendation

**Option a.** It is ahead of ManageEngine, which publishes no window, so it counts as an enhancement. It is costly to keep only for operations we actually deprecate, and ADR-0004 makes that rare because additive change is free. Revisit toward 24 months (option b) as a new decision once real deprecations show the cost. Lengthening a promise later is easy, but shortening one is a breach.

Add these terms to the published policy under any option:

1. The window counts from the release that first sends `Deprecation`/`Sunset`, and `x-activediq-sunset` names the first release allowed to remove it.
2. Applies to `stable` operations only. `preview` carries no promise.
3. Security or reliability emergencies are the only exception, announced with the reason.
4. Self-hosted customers who skip releases are covered by the *months* floor, not just the release count. This is why "whichever is longer" matters.

## Reversibility

Before GA: free. After GA: lengthening is free, shortening breaches a published promise. So the risky choice is promising more than we can keep; starting at a window we are sure of and lengthening later is safe.

## Decision request (for the director to file)

- Kind: `directional`. One question: "Which deprecation window do we publish for stable API operations?"
- Options a, b, c as above, a first. Context ≤150 words. Needs an answer before the GA release checklist is written. No default on timeout.
