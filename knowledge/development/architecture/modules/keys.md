---
title: "platform/keys: KEK provider, DEK wrap, AEAD seal"
date: 2026-10-22
updated: 2026-10-22
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
  The server feeds `LocalProvider` from the interim file KEK profile (`ACTIVEDIQ_KEK_FILE`, T-0407; threat model
  TM-TB5-T7): linux-oci/dev only, until the passphrase keystore or OS/KMS adapters land.
- `DEK` holds its bytes in a `secret.Secret` (DM-02.I3): redacted when printed, zeroed by `Destroy`.
- Not here: DM-02 table/migration, active-version selection, rotation/re-seal job (T-0007/TM-D15), shredding.
  Callers call these inside the tenant's `WithTenantTx`.
- Limit: random nonces under one DEK are safe to ~2^32 seals; the rotation job bounds this.
