---
title: "Key custody addendum to ADR-0002: server-role KEK bootstrap, tenant DEK lifecycle, DM-02 table"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: solution-architect
ticket: T-0522
sources_last_checked: 2026-10-28
---

# Key custody: KEK bootstrap and DM-02 TenantKey lifecycle

Addendum to [ADR-0002](../decisions/0002-deployment-model.md) ("Keys and secrets"), which fixes the model:
a tenant data key (DEK) wrapped by an installation KEK from the profile's key-provider adapter. This
document specifies what ADR-0002 left open. It adds no new CEO-level decision. Domain: DM-02
([domain-model](../domain/domain-model.md)); threat rows TM-TB5-T1..T5, TM-D7, TM-F-SEAL
([threat-model](threat-model.md)); code: `internal/platform/keys/` ([module note](modules/keys.md)).
Status `draft` until security-architect reviews it; it becomes ADR-0002's accepted addendum when
FF-KEY-1..6 (below) are green in `make ci`.

## 1. Decisions

| # | Decision |
| --- | --- |
| K1 | **The KEK is selected and read only in the composition root** (`internal/compose/server`), through one typed `KEKConfig`. Domain and platform packages receive a `keys.Provider`. Never the environment, never a path. |
| K2 | **No auto-generation of key material at server start.** The KEK is created by an explicit command (`activediq-server kek init`), run by the installer/prepare script or the operator. A server that finds no KEK, or a KEK that does not match DM-02, **refuses to start**. Regenerating silently would orphan every sealed value. |
| K3 | **First DEK is eager and idempotent**: `keys.Store.Provision` is a per-tenant initialiser (like `audit.InitTenant`), run by tenant creation immediately after the `tenants` row commits, in the tenant's own `WithTenantTx`. If the provider is down, creation returns the error and the tenant exists but is **keyless and unusable** (`KeySource` returns `NoActiveKey`, boot sweep fails closed) until the initialiser is re-run, which every `provision.FirstRun`/tenant-create retry does. There is no lazy creation anywhere; `KeySource.DEK` has no INSERT path. |
| K4 | **One module owns `tenant_keys`**: only `internal/platform/keys` (and its SQL sub-package) references the table in SQL (same pattern as `personal`). |
| K5 | **Fail closed, non-leaking**: every failure is a `*keys.Error` with a stable code. API, logs and audit carry the code only. |
| K6 | **Per-profile adapters implement the one `keys.Provider` interface.** M1 ships `passphrase` (the `LocalProvider`); `dpapi-ng`, `tpm2`, `kms`, `vault` are later adapter tickets with no change to this document's table shape. |

## 2. KEK provider configuration and bootstrap, per profile

Platform-scope configuration (ADR-0002: installation operator sets it; tenant admins never touch it).
One selector, then provider-specific keys. All are read by `compose/server` into `KEKConfig` and
validated at startup; an unknown value, a missing required key or a provider-specific key for another
provider **fails startup**.

| Setting | Meaning |
| --- | --- |
| `ACTIVEDIQ_KEK_PROVIDER` | `passphrase` \| `dpapi-ng` \| `tpm2` \| `kms` \| `vault`. **No default**: unset fails startup (a default would pick a custody model silently). |
| `ACTIVEDIQ_KEK_DIR` | Directory of the keystore file(s) (local providers). Same ownership/permission rule as `ACTIVEDIQ_API_TLS_DIR` (owned by the server user, not group/other-writable, key files 0600, regular files only). |
| `ACTIVEDIQ_KEK_PASSPHRASE_FILE` | `passphrase` only: path to a file holding the passphrase (systemd `LoadCredential`, Docker/Kubernetes secret mount). **A passphrase value is never accepted in an environment variable, flag, config file or the database** (TM-TB5-T4). Must not be inside `ACTIVEDIQ_KEK_DIR`. |
| `ACTIVEDIQ_KEK_KMS_KEY` / `…_VAULT_*` | KMS key id / Vault transit path and auth reference. Credentials come from the workload identity (instance role, gMSA, Kubernetes service account), never a static secret in config. |

| Profile | Providers allowed | Bootstrap (`kek init`) | Start-up |
| --- | --- | --- | --- |
| `windows` | `dpapi-ng` (descriptor bound to the service identity, e.g. the gMSA SID), `tpm2` optional. `passphrase` allowed for lab only (startup validation refuses it unless `ACTIVEDIQ_LAB=1`). | MSI post-install action runs `kek init`: generates a random 32-byte KEK, protects it with DPAPI-NG (and TPM where present), writes the protected blob to `ACTIVEDIQ_KEK_DIR`. `[UNVERIFIED — Windows lab: DPAPI-NG descriptor semantics for gMSA on a non-domain-joined host]` (TM-TB5-T1) | Unprotect as the service identity; self-test (below). |
| `linux-oci` | `passphrase` (default for the OCI image), `tpm2`, `kms`, `vault`. | Prepare script / `docker run … kek init` before first `serve`. For `passphrase` the operator is prompted (or supplies the secret file) once. | Reads the passphrase from the secret file; no prompt in a headless service. |
| `saas` | `kms` only; `passphrase` refused. | Provisioned by skenzeriq operations with the cell; the KMS key and its encryption-context policy are infrastructure. `kek init` is a no-op that verifies reachability. | KMS call with encryption context `tenant_id` / `platform:<purpose>`. |

**The `passphrase` keystore** (the M1 deliverable). `kek init` generates a random 32-byte KEK and a
random `key_id`, derives a key-encrypting key from the passphrase with Argon2id (parameters and salt
stored in the file), and stores only the KEK **sealed under that key** in `kek.keystore.json`
(`{format, kdf{alg,m,t,p,salt}, key_id, sealed_kek}`). The KEK is therefore independent of the
passphrase: changing the passphrase re-seals the file and re-wraps no DEK. Unlock failure is
indistinguishable between wrong passphrase and corrupt file (`UnwrapFailed`-class, no oracle). Argon2id
comes from `golang.org/x/crypto`, currently a transitive **Candidate** in the
[licence register](../../business/licensing/open-source-license-register.md) (BSD-3-Clause); adopting it
directly needs its register row set to Approved first (follow-up ticket records it).

**Start-up self-test (all providers), in order, any failure aborts startup with a one-line code:**
1. Keystore/provider reachable and unlocks (`ProviderUnavailable` or `UnwrapFailed`).
2. Round trip `WrapPlatform`/`UnwrapPlatform` of random bytes under purpose `kek-selftest`.
3. **KEK matches the data (no tenant context needed).** Read the one row of the registered-global
   table `installation_kek` (§4a) inside `WithPlatform(ctx, "keys.boot-check", …)`: it is global, so it
   is visible with no tenant set and RLS is not involved. If a row exists, the provider's
   `Ref()` must equal its `(kek_provider, kek_key_id)` (or an older ref the provider still holds) **and**
   `Provider.UnwrapPlatform(check_value)` under purpose `kek-check` must succeed and return the stored
   canary; otherwise start fails
   (`KekMismatch`). This is the "restored the database but lost the keystore" guard (TM-TB5-T5). It does
   not depend on DM-02 rows, so RLS cannot make it see "empty". Recovery is re-entering the original credentials; the passphrase file and database backups must never share a backup set (TM-TB5-T4: `passphrase` custody is only as strong as that host's file permissions); the KEK backup procedure is a runbook item `[OPEN → E2.12 PRD]`.
4. **No keyless live tenant.** If `installation_kek` has **no row**, the installation must be fresh:
   the tenant package's port `tenant.Live(ctx)` (called inside the same `WithPlatform` site; `keys` never names the `tenants` table, T5 `global-table-sql`) must report no non-`deleted` tenant, else start fails
   (`NoInstallationKek`: a database that has tenants but lost its key record is a restore, not an
   install). If a row exists, the sweep in §3a verifies each live tenant has an active key; any gap fails
   start with `NoActiveKey` (fail closed; the operator runs `keys provision --missing`, §3, which is the
   only command that starts without this check).

**Multi-node.** Every node gets the same keystore and secret by the installation mechanism (shared
secret mount or the same KMS key). A node that cannot unlock fails its own startup; it never serves.
KEK rotation across nodes (keyring with a current and previous KEK, re-wrap job) is out of this
ticket's build scope: single-KEK `LocalProvider` rejects a `kek_ref` it does not hold. Follow-up below.

**Wrap binding (all providers, TM-D7, TM-TB5-T2).** Every `wrapped_dek` is AEAD-sealed with associated
data `(tenant_id, version, kek_provider, kek_key_id)` (KMS: the same values in the encryption context,
plus the existing `tenant_id`). Copying a wrapped DEK to another tenant row or version, or editing
`kek_key_id`, makes unwrap fail (`UnwrapFailed`). The `passphrase` file's `sealed_kek` binds
`(format, kdf, key_id)` as associated data, and the loader enforces an Argon2id floor and ceiling
(`m` 19 MiB-1 GiB, `t` 2-10, `p` 1-16) so a doctored file can neither downgrade the KDF nor exhaust memory.

## 3. First DEK policy: eager

- `keys.Store.Provision(ctx, tx, tenant)` generates a DEK (`NewDEK(1)`), wraps it
  (`WrapDEK`), inserts version 1 `active`, destroys the plaintext. It runs in the new tenant's own
  `WithTenantTx` (RLS applies), **after** the `tenants` row commits: `tenants` is inserted under
  `WithPlatform` (no tenant context), so the two cannot share a transaction. This is the
  `provision.FirstRun` pattern ([tenancy-fitness](tenancy-fitness.md): row commits first, idempotent
  initialisers run on every call and complete a half-initialised tenant). It is idempotent: it does
  nothing if the tenant already has any `tenant_keys` row. Guarantee: **a tenant without an active key
  can exist for a moment but can never be used**: no sealed operation succeeds (`NoActiveKey`), the
  tenant is not offered by the API as ready, and boot refuses to serve (§2 step 4).
- Self-hosted: the installer's single tenant is created by `provision.FirstRun` with `keys.Store.Provision` as one of its initialisers.
- Existing tenants without a key (dev databases from before this design): the explicit, idempotent
  command `activediq-server keys provision --missing`: list tenants through the tenant package's port
  (`tenant.Live`; `tenants` is registered-global and owned by `tenant`; the call is one `WithPlatform(ctx, "keys.provision-missing", …)` site
  in the registry), then **for each tenant** open its own `WithTenantTx`, take `pg_advisory_xact_lock`
  on the tenant, **refuse unless** the tenant is live (state not `deleting`/`deleted`) **and has zero `tenant_keys` rows of any state**; a tenant with only retired/shredded rows, or one in `deleting`, is reported and skipped, never re-keyed (a tenant that should have keys but has none after a partial restore is exactly the silent re-key §3 rejects, so the command lists such tenants and requires the explicit flag `--tenant <id> --confirm-no-prior-data` per tenant). It skips **only** the §2 step 4 sweep; steps 1-3 (provider, round trip, `installation_kek` match) always run. It never reads `tenant_keys` without a
  tenant context and never needs SECURITY DEFINER or BYPASSRLS. Operator-run, never triggered by a request.

**Registry entries (added with the code, T-0520/T-0525):** `WithPlatform` sites `keys.boot-check` and
`keys.provision-missing` (each with reason and owner), and the global table `public.installation_kek`
(owner `internal/platform/keys`).

### 3a. The cross-tenant path (the only one)

Anything that must look at every tenant's keys (boot sweep, `keys provision --missing`, `keys rewrap`,
`keys verify`) uses **list tenants via `WithPlatform`, then one `WithTenantTx` per tenant**, sequential
or with bounded parallelism (default 8). No role, policy or function widens RLS on `tenant_keys`; T2/T3
and the SECURITY DEFINER ban hold unchanged. Boot-sweep cost is O(live tenants) single-row reads;
self-hosted has one, and a SaaS cell runs the sweep concurrently after `serve` is gated closed
(readiness stays false until it finishes). A sweep error on any tenant is a start failure, not a skip.
- **Rejected: lazy creation on first seal.** It puts a key-provider dependency and a write on a
  request path, creates a race between nodes (two active DEKs, or a unique-violation retry loop),
  and lets a missing key mask a restore error (a tenant whose key row was lost would silently get a
  new key, orphaning old ciphertext). Eager failure is visible at the only moment it is cheap.

## 4. DM-02 `tenant_keys` table

Tenant table (`T`), forced RLS from its first migration, declared in code with
`tablekind.Declare{Name: "public.tenant_keys", Entity: "DM-02", Kind: tablekind.Tenant, Sealed: ["wrapped_dek"]}`
so X3/X4 and the table registry cover it.

```sql
CREATE TABLE public.tenant_keys (
  tenant_id     uuid        NOT NULL REFERENCES public.tenants (id),
  version       integer     NOT NULL CHECK (version > 0),
  state         text        NOT NULL CHECK (state IN ('active','retired','shredded')),
  wrapped_dek   bytea       NOT NULL,          -- AEAD blob from Provider.Wrap; empty iff shredded
  kek_provider  text        NOT NULL,          -- DM-02 kek_ref.provider
  kek_key_id    text        NOT NULL,          -- DM-02 kek_ref.key_id; pinned per version (TM-TB5-T2)
  created_at    timestamptz NOT NULL DEFAULT now(),
  retired_at    timestamptz,
  shredded_at   timestamptz,
  PRIMARY KEY (tenant_id, version),
  CHECK ((state = 'shredded') = (octet_length(wrapped_dek) = 0)),
  CHECK ((state = 'shredded') = (shredded_at IS NOT NULL)),
  CHECK (state <> 'active' OR retired_at IS NULL),            -- an active row was never retired
  CHECK (state <> 'retired' OR retired_at IS NOT NULL)
);
CREATE UNIQUE INDEX tenant_keys_one_active ON public.tenant_keys (tenant_id) WHERE state = 'active';  -- DM-02.I1
ALTER TABLE public.tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_keys FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_keys_tenant ON public.tenant_keys
  USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
```

**Tenant FK (T2 `fk-pairs-tenant-id`).** `tenant_id` is the table's own FK to `tenants(id)` and the leading
PK/unique-index column; `tenant_keys` has no other foreign key, so nothing else needs to pair `tenant_id`.

**Grants to `activediq_app`**: `SELECT`, `INSERT`; `UPDATE (state, retired_at, shredded_at, wrapped_dek)`
(`wrapped_dek` only to empty it on shred, enforced by the trigger); **no UPDATE on `kek_provider`/`kek_key_id`
(re-wrap runs as the owner role, §5), no DELETE, no TRUNCATE** (the retention/purge role removes shredded
tombstones after the tenant's `deleted` transition). `tenant_id`, `version`, `created_at` are immutable.

**Transition trigger** (BEFORE UPDATE, plus an AFTER trigger refusing `tenant_id` change as in 0041):

| From → to | Allowed | Column changes allowed |
| --- | --- | --- |
| `active → retired` | yes | `state`, `retired_at` (rotation, §5) |
| `active|retired → shredded` | yes | `state`, `shredded_at`, `wrapped_dek := ''` |
| `active|retired → same` | yes, **re-wrap only, and only when `current_user = 'activediq_owner'`** (the `keys rewrap` maintenance command, §5; the runtime role has no column grant and the trigger refuses it too) | `wrapped_dek`, `kek_provider`, `kek_key_id` (KEK rotation; the plaintext DEK is unchanged) |
| `retired → active`, `shredded → *` | **never** | — |

**Invariants:** DM-02.I1 (one active) by the partial unique index; I2 sealed values record `version`
in their blob (already in `keys.Seal`); I3 no plaintext column exists; I4 shredding is §5.

### 4a. `installation_kek` (registered-global, owner `internal/platform/keys`)

One row per installation (SaaS: per cell); it records *which* KEK the data belongs to, never key
material. Not a tenant table: no `tenant_id`, no FK to a tenant table (T2 `global-references-tenant`).
Registered in the exemption registry with reason and owner `internal/platform/keys`; only that package's
SQL references it (T5).

```sql
CREATE TABLE public.installation_kek (
  singleton     boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  kek_provider  text        NOT NULL,
  kek_key_id    text        NOT NULL,
  check_value   bytea       NOT NULL CHECK (octet_length(check_value) > 0),   -- WrapPlatform(canary, purpose 'kek-check')
  created_at    timestamptz NOT NULL DEFAULT now()
);
```

Runtime role: `SELECT, INSERT` only (no UPDATE/DELETE/TRUNCATE). `Provision` inserts it
(`ON CONFLICT DO NOTHING`, then verifies equality) in the transaction that creates the installation's
**first** tenant key. KEK rotation (follow-up F2) replaces it through the owner-role `keys rewrap`
command. `check_value` is a wrapped fixed public canary (`WrapPlatform`, purpose `kek-check`), so the check needs only the Provider interface and works for non-exportable KEKs (`kms`, `vault`, `tpm2`); the raw KEK is never required. A wrapped known plaintext is ordinary AEAD output and leaking the table does not weaken custody.

## 5. Lifecycle: rotation and shred states

`active → retired (decrypt-only) → shredded` (domain model). **Who may call what.** `Rotate` and `ShredTenant` are reachable only from (a) the registered platform-scope
Actions `keys.dek.rotate` and `tenant.delete` (ADR-0005 pipeline: step-up, audited, platform permission; no
tenant-scope Action, route or job type may carry them) and (b) the tenant-deletion job those Actions
enqueue. The KEK re-wrap (`kek_ref` change, `active→same`) is **not an app path at all**: it is the operator
CLI `activediq-server keys rewrap`, which opens `store.OpenMaintenance` (owner role, refuses superuser and
BYPASSRLS as the audit purger does) and rewraps per tenant inside `WithTenantTx` (§3a). The runtime role
cannot UPDATE the kek columns and the trigger rejects the transition for any other `current_user`.

Operations, all inside the tenant's
`WithTenantTx`, all emit an audit event in the same transaction (`tenant_key.provisioned|rotated|shredded`,
carrying tenant, version and `kek_key_id`, no key material):

- **Rotate DEK** `keys.Store.Rotate`: `SELECT … FOR UPDATE` the active row, set it `retired` **first**, then
  insert `version+1` active (the partial unique index `tenant_keys_one_active` is not deferrable, so the reverse order fails), all in one transaction. New seals use the new version; old blobs still open (`BlobVersion` picks the
  DEK). A re-seal job that moves sealed values to the new version and a rule for when a retired
  version may be shredded alone are **not specified here**: the owning ticket (T-0007 was cancelled and
  its DM-02 Q2 is orphaned) is created as follow-up F2. Until it exists, retired versions are kept.
- **Shred tenant** `keys.Store.ShredTenant`: called by tenant deletion **before** rows are purged
  (DM-01.I5). Sets every version `shredded`, empties `wrapped_dek`, in one transaction, and evicts the
  node's DEK cache. Irreversible.
- **Audit and operators.** `kek init`, `keys provision`, `keys rewrap` and the creation of `installation_kek`
each emit an audit event with an attributable operator identity (OS user / service principal), no key
material. Shredding a tenant's DEK also makes that tenant's sealed audit checkpoint key unreadable, so
audit export or attestation must complete **before** deletion (deletion runbook). The `current_user =
'activediq_owner'` trigger check is sound because T3 forbids the runtime role any membership in the owner
role. The transition trigger also asserts every column not listed for a transition is unchanged.
Residual risk (for the threat model): SQL injection at runtime privilege could retire or shred its own
tenant's keys (UPDATE on `state` is granted); the FF-KEY-2 scan covers Go only.

**Honest limit of crypto-shredding.** A database backup or WAL archive taken before the shred still
  holds the wrapped DEK, which the (unchanged) KEK can unwrap. Shredding is complete for the live
  system; for backups it is complete only once backups older than the shred age out, or the KEK that
  wrapped those versions is retired. With a per-installation KEK the KMS cannot shred one tenant. This
  is stated in the tenant-deletion runbook and the customer-facing data-handling statement, not hidden.
- **DEK cache.** `KeySource` may cache an unwrapped DEK per `(tenant, version)` in memory for at most
  60 seconds (entries zeroed on expiry and on shred). Other nodes therefore stop using a shredded key
  within 60 s; the `deleting` tenant state already refuses new operations earlier. Unwrap count per
  tenant is a metric (TM-TB5-T3, T-0177): `activediq_keys_dek_unwraps_total{tenant,outcome}`, counted in `keys.UnwrapDEK` (`internal/platform/keys/metrics.go`), so every provider profile is covered.

## 6. `KeySource` and failure behaviour

`keys.Store.KeySource()` implements the existing `DEK(ctx, tx, tenant, version)` port used by `authn`,
`audit` and `fleetsql` (version 0 = active). It reads `tenant_keys` through the caller's tx (so RLS
scopes it), unwraps through the provider and returns a `keys.DEK` the caller destroys.

| Condition | Code | Surfaces as |
| --- | --- | --- |
| Provider unreachable / outage / timeout | `ProviderUnavailable` | 503, retryable, no detail |
| No active row for a tenant | `NoActiveKey` (new) | 500-class internal; ops alert |
| Version unknown **or** another tenant's (RLS hides it; indistinguishable) | `KeyNotFound` (new) | internal |
| Version is `shredded` | `KeyShredded` (new) | internal; tenant is deleting/deleted |
| Wrapped DEK fails to authenticate, or `kek_ref` not held | `UnwrapFailed` | internal; ops alert |
| Boot only: `installation_kek` names another KEK / check value, or tenants exist with no record | `KekMismatch`, `NoInstallationKek` (new) | startup abort, one-line code in the operator log |
| Provider returns a DEK of wrong size or version mismatch | `InvalidKey` | internal |

Rules: no plaintext fallback, no default key, no retry that substitutes another key. The error text is
`keys: <Code>` only: never the tenant id, version, `kek_key_id`, provider name, SQL text or a path
(those go to the **operator log** at ERROR keyed by code, with tenant id, which is already in that log's
context, but never in the API problem body or the audit event). The API problem for every non-503 code
is the same generic internal-error type, so a caller cannot tell "no key" from "shredded" from "bad
wrap" (no oracle). `StepUp.TOTP`, checkpointing and CA sealing treat any `KeySource` error as
operation failure and never proceed unsealed.

## 7. Fitness function (accepted only when green in `make ci`)

New job `make fitness-keys` (`tools/fitness/keycustody`), plus declarations picked up by existing jobs.

| ID | Fails the build when |
| --- | --- |
| FF-KEY-1 | **Schema.** On the migrated schema: `tenant_keys` is missing, not `FORCE` RLS, lacks the partial unique active index or the transition trigger; `activediq_app` holds DELETE/TRUNCATE or UPDATE on `tenant_id`/`version`/`created_at`. `installation_kek` missing, not registered-global, or the runtime role holds UPDATE/DELETE on it. Declaration `Sealed: wrapped_dek` absent (domain-keys REG/X4 already fail an undeclared table). |
| FF-KEY-2 | **Single owner (AST/string scan).** Any Go source outside `internal/platform/keys` and the migrations references `tenant_keys`; or calls `keys.NewDEK`, `keys.DEKFromBytes`, `Provider.Wrap`/`Unwrap`, `WrapDEK` or `UnwrapDEK` outside `internal/platform/keys`, `keystest` and `compose/server`. |
| FF-KEY-3 | **Config only in the root.** `ACTIVEDIQ_KEK_*` is read by anything but `internal/compose/server`; any config struct, flag or DB column carries a passphrase/KEK value; `ACTIVEDIQ_KEK_PROVIDER` has a default. |
| FF-KEY-4 | **Boot tests (integration).** Server start fails with a one-code error and never serves when: provider unset; keystore missing; passphrase wrong; keystore present but `installation_kek` names another KEK or check value; provider unreachable. **Rows exist, no tenant context** (the boot check runs with none): a database with live tenants and `tenant_keys` rows but a freshly `kek init`-ed keystore must fail `KekMismatch`; one with live tenants and no `installation_kek` row must fail `NoInstallationKek`; a live tenant without an active key must fail `NoActiveKey`, and `keys provision --missing` must then repair it using only per-tenant `WithTenantTx` (the test also asserts no SECURITY DEFINER/BYPASSRLS exists, via T2/T3). No test path succeeds by falling back to plaintext or to a generated key. |
| FF-KEY-5 | **Eager, not lazy.** A test creates a tenant with a failing provider and asserts the tenant is keyless, every sealed operation returns `NoActiveKey`, boot refuses, and a retry of the initialiser completes it; `provision --missing` cases: a tenant with a shredded row and one in `deleting` are skipped, never re-keyed; an AST check asserts the only `INSERT INTO tenant_keys` statements are in `Provision` and `Rotate`, never reachable from `KeySource`. **Callers:** `Rotate`/`ShredTenant` are called only from the packages of the two registered Actions and the deletion job; `keys rewrap` is the only user of `OpenMaintenance` in `keys`; the trigger test proves the runtime role cannot perform `active→same` re-wrap. |
| FF-KEY-6 | **Non-leaking.** For each failure row in §6, the error string, the API problem body and the audit event contain none of: tenant id, version, `kek_key_id`, provider name, a path, SQL. Cross-tenant: tenant B's tx asking for tenant A's version gets `KeyNotFound`, identical in body to a nonexistent version. Wrap-binding case: a wrapped DEK moved to another tenant row or version, or with edited `kek_key_id`, fails `UnwrapFailed`. FF-KEY-4 also runs against a fake non-exportable provider (no raw KEK access). Property test on the transition table (§4): no sequence reaches `retired → active` or leaves a shredded row with non-empty `wrapped_dek`. |

## 8. Follow-up tickets

| Ref | Ticket | Owner |
| --- | --- | --- |
| F1 | `make fitness-keys` (FF-KEY-1..6) as stubs-red-until-built; wire into `make ci` | devops-engineer |
| F2 | DEK rotation orchestration: re-seal job over sealed columns, rule for shredding a retired version, KEK keyring rotation (current + previous KEK, re-wrap job); replaces cancelled T-0007 for DM-02 Q2 | backend-engineer, security-architect reviews |
| F3 | Production providers: `dpapi-ng`/`tpm2` (Windows lab to verify descriptor semantics), `kms`, `vault` adapters behind `keys.Provider` | backend-engineer (windows-engineer for DPAPI-NG) |
| F4 | Licence register: Argon2id via `golang.org/x/crypto` to Approved | devops-engineer |
| T-0520 | Build of §2 passphrase keystore + `kek init`, §3 `Provision`/`keys provision --missing`, §4 migration, §6 `KeySource`. Scope grew beyond its first note: the keystore/`kek init` command and boot self-test are in. | backend-engineer |
