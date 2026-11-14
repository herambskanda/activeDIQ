package rbac

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrReadScopesUnbound is returned by TxReadScopes before Bind: the producer is not wired yet, so
// nothing is answered (fail closed), never an unscoped read.
var ErrReadScopesUnbound = errors.New("rbac: read-scope producer is not bound yet")

// TxReadScopes is the read-scope producer a module holds from construction (platform.Deps.ReadScopes).
// ReadScopes reads in a caller's transaction and needs the EP-6 evaluators the modules contribute, so it
// can only be built after Boot; a module is built before it. TxReadScopes closes that gap: modules keep
// this value, the composition root calls Bind once the producer exists, and every ReadScope call opens
// the tenant transaction the producer needs. Before Bind it refuses every call.
type TxReadScopes struct {
	db *store.DB
	rs atomic.Pointer[ReadScopes]
}

// NewTxReadScopes returns an unbound producer over db.
func NewTxReadScopes(db *store.DB) *TxReadScopes { return &TxReadScopes{db: db} }

// Bind sets the producer. It is called once by the composition root after Boot.
func (t *TxReadScopes) Bind(rs *ReadScopes) error {
	if t == nil || rs == nil {
		return errors.New("rbac: bind needs a producer")
	}
	if !t.rs.CompareAndSwap(nil, rs) {
		return errors.New("rbac: read-scope producer is already bound")
	}
	return nil
}

// ReadScope returns the caller's read scope for perm, in a tenant transaction.
func (t *TxReadScopes) ReadScope(ctx context.Context, tid tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error) {
	if t == nil || t.db == nil {
		return authz.ReadScope{}, ErrReadScopesUnbound
	}
	rs := t.rs.Load()
	if rs == nil {
		return authz.ReadScope{}, ErrReadScopesUnbound
	}
	var out authz.ReadScope
	err := t.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = rs.For(ctx, tx, tid, chain, perm)
		return err
	})
	if err != nil {
		return authz.ReadScope{}, err
	}
	return out, nil
}
