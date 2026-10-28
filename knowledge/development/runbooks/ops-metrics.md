---
title: Operator metrics endpoint and alert rules
date: 2026-10-28
updated: 2026-10-28
ticket: T-0533
status: draft
owner: backend-engineer
---

# Operator metrics (`/metrics`)

Off by default. Enable with `ACTIVEDIQ_OPS_ADDR` (e.g. `127.0.0.1:9100`) **and**
`ACTIVEDIQ_OPS_TOKEN_FILE` (a 0600 file owned by the service user holding a random token of at least
32 bytes, e.g. `openssl rand -hex 32`). The listener is TLS-only (the API's per-install certificate),
serves nothing but `GET /metrics`, and accepts only that token as `Authorization: Bearer …`. A tenant
session or tenant API key gets 401. It must differ from `ACTIVEDIQ_API_ADDR`; a non-loopback bind
needs `ACTIVEDIQ_API_TLS_DIR`. Restrict the port to the scraper at the network layer too.

Why separate: the series carry every tenant ID and per-tenant activity, i.e. cross-tenant information
in SaaS (TM-TB17-T8, TM-F-PORTS).

## Series

`activediq_keys_dek_unwraps_total{tenant,outcome}` — counter of DEK unwraps; `outcome` is `success`
or `failure`. No key reference, key id or wrapped material appears.

## Alert rule: unwrap-failure spike per tenant (TM-TB5-T3 detection)

```yaml
- alert: ActiveDIQDekUnwrapFailureSpike
  expr: sum by (tenant) (increase(activediq_keys_dek_unwraps_total{outcome="failure"}[10m])) > 5
  for: 5m
  labels: {severity: page}
  annotations:
    summary: "Repeated DEK unwrap failures for tenant {{ $labels.tenant }}"
```

Threshold is a starting point: failures that are a wrong-tenant or wrong-key attempt, or a KEK
unavailable, all look alike here; correlate with the provider's own audit log (e.g. CloudTrail). The
counter is per process and resets on restart, so use `increase()`/`rate()`, never the raw value.
