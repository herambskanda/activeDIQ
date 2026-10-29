---
title: "platform/keys: KEK provider, DEK wrap, AEAD seal"
date: 2026-10-22
updated: 2026-10-28
status: draft
owner: backend-engineer
ticket: T-0126
---

# platform/keys (TM-D7, DM-02)

Code: `internal/platform/keys/`; fake KMS: `internal/platform/keys/keystest/`.

- `Seal(dek, Context, pt)` / `Open(dek, Context, blob)`: AES-256-GCM, random 96-bit nonce, associated data =
  length-prefixed `(tenant_id, table, row, column)` + `key_version`. Blob = `format(1) | version(4) | nonce(12) | ct+tag`.
  Any differing component, any flipped byte or a wrong key gives a typed `*keys.Error` (`OpenFailed`,
  `KeyVersionMismatch`, `MalformedBlob`) and nil plaintext. `BlobVersion` lets a re-seal job pick the DEK.
- `keys.Provider` (EP-12): `Wrap`/`Unwrap` of a DEK with `WrapRequest{Tenant, Version}` as the encryption
  context. `LocalProvider` (AES-GCM KEK, binds tenant, version and `kek_ref` into the AAD) serves the
  passphrase/test profile; KMS, Vault, DPAPI-NG and TPM adapters implement the same interface later.
  The server feeds `LocalProvider` from the passphrase keystore (T-0655; threat model TM-TB5-T7).
- `keys.CreateKeystore` / `keys.OpenKeystore` (`keystore.go`): the `kek.keystore.json` format
  `{format, kdf{alg=argon2id,m,t,p,salt}, key_id, sealed_kek}` and its crypto only (Argon2id from `golang.org/x/crypto`,
  loader floor/ceiling on m, t, p; AAD binds every field). Wrong passphrase, corrupt file and out-of-range KDF are one
  `UnwrapFailed`. File access, `KEKConfig` and `activediq-server kek init` live in `internal/compose/server`
  (`kekconfig.go`, `kekinit.go`, `keyprovider.go`), the only readers of `ACTIVEDIQ_KEK_*`.
- `keys.WriteMetrics` renders `activediq_keys_dek_unwraps_total{tenant,outcome}` in Prometheus text format (label values
  escaped per the exposition format). It is cross-tenant data, so it is served only by `internal/platform/opsmetrics`
  on the optional operator listener (bearer token, never the API listener; see `api-pipeline.md`, T-0533).
- `DEK` holds its bytes in a `secret.Secret` (DM-02.I3): redacted when printed, zeroed by `Destroy`.
- `keys.Store` (T-0520, `store.go`; migration `0053_keys_tenant_keys.sql`; design: [keys-custody-design](../keys-custody-design.md) §3, §4, §6):
  the only code that references `tenant_keys` (DM-02: forced RLS, one active row per tenant, transition trigger,
  no DELETE/TRUNCATE for the runtime role). `Provision(ctx, tx, tenant)` is the eager, idempotent first-DEK
  initialiser (version 1 active; a tenant with any row is left alone). `Store.KeySource().DEK(ctx, tx, tenant, version)`
  is the read-only port authn/audit/fleetsql consume (version 0 = active); its only failure texts are `keys: <Code>`
  (`NoActiveKey`, `KeyNotFound`, `KeyShredded`, `ProviderUnavailable`, `UnwrapFailed`, `StoreFailed`). It has no INSERT path
  (AST test). Not yet built: `Rotate`, `ShredTenant`, `installation_kek` and the boot self-test, `keys provision --missing`, the DEK cache (follow-up tickets).
- Installation scope (T-0715, `installation.go`; migration `0054_keys_installation_keys.sql`; ADR-0008): one DEK for the
  installation, sealing the fleet SERVER CA key only (per-tenant client CAs stay under tenant DEKs). `SealInstallation` /
  `OpenInstallation` use `InstallationContext{Table,Row,Column,Version}` (no tenant; AAD tag `diq.seal.installation.v1`), the
  DEK is wrapped as platform purpose `installation-dek`, so a tenant blob/wrap never opens as it and it never opens as a
  tenant's (`OpenFailed` / `UnwrapFailed`). `InstallationKeys.DEK(ctx, tx, version, reason)` (run in `WithPlatform`; 0 = active)
  creates version 1 on first use (partial unique index ⇒ concurrent creators end with one active row), unwraps through the
  boot-unlocked provider on every call (no cache; KEK down ⇒ `ProviderUnavailable`), and audits every access through the
  `InstallationAuditor` port the composition root adapts to the platform audit sink. The port is durable: each record commits
  on its own, independent of the caller's tx (failure records survive a rollback; the success record commits before the DEK is
  handed out, else `AuditFailed`); only the creator whose INSERT took effect records `create`. Table `installation_keys` is registered-global, runtime role SELECT+INSERT only. Not built: rotation,
  the audit-sink adapter and the `fleet_server_ca` consumer (T-0716 line of work).
- Not here: re-seal job (TM-D15). Callers call these inside the tenant's `WithTenantTx`.
- Limit: random nonces under one DEK are safe to ~2^32 seals; the rotation job bounds this.
