package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// accountUUID is the shape of an authn account id. An id of any other shape is no account, and is
// answered before the database, so a malformed id is "inactive" rather than a cast error.
var accountUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// accountOwnerStatus serves rbac.OwnerStatus from the authn account store, in the caller's transaction.
type accountOwnerStatus struct{}

// Active reports whether account is an active account of t. An invited, disabled or deleted account,
// an account of another tenant and an unknown or malformed id are all not active.
func (accountOwnerStatus) Active(ctx context.Context, tx store.Tx, t tenant.ID, account string) (bool, error) {
	if tx == nil || t.IsZero() {
		return false, errors.New("server: owner status needs a tenant transaction")
	}
	if !accountUUID.MatchString(account) {
		return false, nil
	}
	var active bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.authn_accounts
		WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active')`, t.String(), account).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("server: reading account state: %w", err)
	}
	return active, nil
}

// inventoryObjectConnections serves rbac.ObjectConnections from inventory's directory_objects, in the
// caller's transaction.
//
// An object counts in whatever state its row is in: the row is what the ancestry of its descendants
// names, and a token's scope root only ever narrows, so keeping a deleted root resolvable cannot widen
// a read. What it refuses is ambiguity: a GUID in two connections resolves to nothing.
type inventoryObjectConnections struct{}

// ConnectionOf returns the connection holding object in t. ok is false when no connection has it, and
// when more than one does.
func (inventoryObjectConnections) ConnectionOf(ctx context.Context, tx store.Tx, t tenant.ID, object authz.ObjectID) (authz.ObjectID, bool, error) {
	if tx == nil || t.IsZero() {
		return authz.ObjectID{}, false, errors.New("server: object connections need a tenant transaction")
	}
	if object.IsZero() {
		return authz.ObjectID{}, false, nil
	}
	// LIMIT 2 is enough to tell one from several; the index is (tenant_id, object_guid).
	rows, err := tx.Query(ctx, `SELECT connection_id::text FROM public.directory_objects
		WHERE tenant_id = $1::uuid AND object_guid = $2::uuid LIMIT 2`, t.String(), report.GUIDString(object))
	if err != nil {
		return authz.ObjectID{}, false, fmt.Errorf("server: finding object connection: %w", err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return authz.ObjectID{}, false, fmt.Errorf("server: finding object connection: %w", err)
		}
		found = append(found, c)
	}
	if err := rows.Err(); err != nil {
		return authz.ObjectID{}, false, fmt.Errorf("server: finding object connection: %w", err)
	}
	if len(found) != 1 {
		return authz.ObjectID{}, false, nil
	}
	conn, err := authz.ParseObjectID(found[0])
	if err != nil {
		return authz.ObjectID{}, false, fmt.Errorf("server: finding object connection: %w", err)
	}
	return conn, true, nil
}

// buildReadScopes constructs the one producer of directory read scopes from the authorizer search and
// reports already share and the EP-6 evaluators the booted modules contributed.
func buildReadScopes(az *rbac.Authorizer, c *module.Contributions) (*rbac.ReadScopes, error) {
	if c == nil {
		return nil, errors.New("server: read scopes need the module contributions")
	}
	rs, err := rbac.NewReadScopes(az, c, accountOwnerStatus{}, inventoryObjectConnections{})
	if err != nil {
		return nil, fmt.Errorf("server: read scopes: %w", err)
	}
	return rs, nil
}

// The composition root's producer is what the directory module asks for (T-0987: buildDirectory gets it).
var _ directory.ReadScopes = txReadScopes{}

// txReadScopes adapts rbac.ReadScopes, which reads in a caller's transaction, to directory.ReadScopes,
// which has none: it opens the tenant transaction the producer needs.
type txReadScopes struct {
	db *store.DB
	rs *rbac.ReadScopes
}

func (s txReadScopes) ReadScope(ctx context.Context, tid tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error) {
	var out authz.ReadScope
	err := s.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = s.rs.For(ctx, tx, tid, chain, perm)
		return err
	})
	if err != nil {
		return authz.ReadScope{}, err
	}
	return out, nil
}
