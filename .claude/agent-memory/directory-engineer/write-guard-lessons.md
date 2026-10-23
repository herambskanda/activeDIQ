---
name: write-guard-lessons
description: connector/write guard build - gRPC wrapper embedding trap, fake Graph needs MS Graph SP, lab creds recipe, test pitfalls
metadata:
  type: feedback
---

- Embedding `UnimplementedConnectorServer` plus a struct with Plan/Apply is ambiguous; wrap the Handler in a named field and forward explicitly. A `*Refusal` with `GRPCStatus()` makes in-process and bufconn gRPC return identical errors (`client.FromStatus` works on both).
- graphtest tenant must contain the Microsoft Graph service principal (appId 00000003-...) or `tier0.Classifier.Snapshot` 404s and every Entra target looks tier0 (fail closed hides the test bug).
- Wire `v1.Guid` is RFC 4122 order; go through `attr/guid.Parse` of the canonical text, never `FromBytes` on wire bytes.
- Freshness tests: when advancing the fake clock, rebuild statements at the new time or STALE masks the gate result you test.
- Lab: `docker inspect activediq-lab-dc-1` env -> lab/.lab.env, `docker cp ...:/var/lib/samba/lab-tls/ca.pem lab/.lab-ca.pem` (both gitignored). Pre-existing safeprim red: ad/schema.go escape-control OID; `tools/fitness` TestFixtureEnvIsClean needs node ajv.
