package keys

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Declared for fitness-domain-keys: DM-02, a tenant table whose wrapped_dek is the sealed column.
var _ = tablekind.Declare(tablekind.Table{Name: "public.tenant_keys", Entity: "DM-02", Kind: tablekind.Tenant, Sealed: []string{"wrapped_dek"}})

// Codes of the DM-02 store (keys-custody-design §6). Like every code they are stable and carry no tenant,
// version, KEK reference, path or SQL.
const (
	NoActiveKey = "NoActiveKey" // the tenant has no active key row: keyless until Provision completes it
	KeyNotFound = "KeyNotFound" // the version is unknown, or another tenant's (row-level security hides it)
	KeyShredded = "KeyShredded" // the version was crypto-shredded
	StoreFailed = "StoreFailed" // the database refused or failed; the cause is kept for operators only
)

const (
	stateShredded = "shredded"
)

// Store persists DM-02 tenant keys. It has no state beyond the provider; every call runs in the caller's
// WithTenantTx, so row-level security scopes it to that tenant.
type Store struct {
	provider Provider
}

// NewStore returns a Store that wraps and unwraps DEKs through p.
func NewStore(p Provider) *Store { return &Store{provider: p} }

// Provision gives the tenant its first key: version 1, active, wrapped under the provider's current KEK.
// It is the only place a tenant's first DEK is created (there is no lazy creation) and it is idempotent: a
// tenant that already has any tenant_keys row, of any state, is left alone, so a retry after a failure
// completes a half-initialised tenant and a tenant whose rows were lost is never silently re-keyed. The
// plaintext DEK is destroyed before it returns, on every path. Run it in the tenant's own WithTenantTx.
func (s *Store) Provision(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	if tid.IsZero() {
		return newErr(InvalidContext)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.tenant_keys WHERE tenant_id = $1::uuid)`,
		tid.String()).Scan(&exists); err != nil {
		return &Error{Code: StoreFailed, err: err}
	}
	if exists {
		return nil
	}
	dek, err := NewDEK(1)
	if err != nil {
		return err
	}
	defer dek.Destroy()
	wrapped, ref, err := WrapDEK(s.provider, tid, dek)
	if err != nil {
		return err
	}
	// ON CONFLICT: a concurrent Provision for the same tenant won the race; that is the no-op case.
	if _, err := tx.Exec(ctx, `INSERT INTO public.tenant_keys (tenant_id, version, state, wrapped_dek, kek_provider, kek_key_id)
		VALUES ($1::uuid, 1, 'active', $2, $3, $4) ON CONFLICT DO NOTHING`,
		tid.String(), wrapped, ref.Provider, ref.KeyID); err != nil {
		return &Error{Code: StoreFailed, err: err}
	}
	return nil
}

// KeySource returns the read side of the store: the DEK(ctx, tx, tenant, version) port that authn, audit and
// fleetsql consume. It has no INSERT path.
func (s *Store) KeySource() *KeySource { return &KeySource{s: s} }

// KeySource gives a tenant's data-encryption key. Version 0 asks for the active version.
type KeySource struct{ s *Store }

// DEK reads the row through tx (the caller's WithTenantTx, so another tenant's rows are invisible),
// unwraps it through the provider and returns a key the caller destroys. It fails closed with a *Error:
// NoActiveKey, KeyNotFound (an unknown version and another tenant's are indistinguishable), KeyShredded,
// ProviderUnavailable, UnwrapFailed or InvalidKey. Retired versions open (decrypt-only).
func (k *KeySource) DEK(ctx context.Context, tx store.Tx, tid tenant.ID, version uint32) (DEK, error) {
	if tid.IsZero() {
		return DEK{}, newErr(InvalidContext)
	}
	var (
		row   = tx.QueryRow
		v     int32
		state string
		wrap  []byte
		ref   KEKRef
		err   error
	)
	if version == 0 {
		err = row(ctx, `SELECT version, state, wrapped_dek, kek_provider, kek_key_id FROM public.tenant_keys
			WHERE tenant_id = $1::uuid AND state = 'active'`, tid.String()).Scan(&v, &state, &wrap, &ref.Provider, &ref.KeyID)
	} else {
		err = row(ctx, `SELECT version, state, wrapped_dek, kek_provider, kek_key_id FROM public.tenant_keys
			WHERE tenant_id = $1::uuid AND version = $2`, tid.String(), int64(version)).Scan(&v, &state, &wrap, &ref.Provider, &ref.KeyID)
	}
	if err != nil {
		if store.IsNoRows(err) {
			if version == 0 {
				return DEK{}, newErr(NoActiveKey)
			}
			return DEK{}, newErr(KeyNotFound)
		}
		return DEK{}, &Error{Code: StoreFailed, err: err}
	}
	if state == stateShredded {
		return DEK{}, newErr(KeyShredded)
	}
	if v <= 0 || (version != 0 && uint32(v) != version) {
		return DEK{}, newErr(InvalidKey)
	}
	return UnwrapDEK(k.s.provider, tid, uint32(v), ref, wrap)
}
