package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxBackedAccounts bounds the accounts one directory object may back. The unique index on
// directory_ref allows one live account per kind (directory, sso), so a larger answer is corruption.
const MaxBackedAccounts = 16

// ErrTooManyAccounts is returned when a directory object backs more than MaxBackedAccounts accounts.
var ErrTooManyAccounts = errors.New("authn: directory object backs too many accounts")

// AccountIndex is the read-only lookup of console accounts by the directory object they rest on. It
// needs only the database, so authorisation can use it without the session machinery Accounts carries.
type AccountIndex struct{ db *store.DB }

// NewAccountIndex returns the index over db.
func NewAccountIndex(db *store.DB) (*AccountIndex, error) {
	if db == nil {
		return nil, errors.New("authn: account index needs a database")
	}
	return &AccountIndex{db: db}, nil
}

// BackedBy returns the IDs of every live (not deleted) account whose directory_ref is the object:
// the directory account of an AD user, and any sso account bound to it by an oid or onprem_sid anchor
// (a binding stores the resolved objectGUID as directory_ref, DM-30.I5). Disabled and invited accounts
// are included: they can be re-enabled. Deleted is final and cannot sign in.
func (x *AccountIndex) BackedBy(ctx context.Context, t tenant.ID, ref DirectoryRef) ([]string, error) {
	if t.IsZero() || !uuidRe.MatchString(ref.ConnectionID) || !uuidRe.MatchString(ref.ObjectGUID) {
		return nil, ErrInvalidInput
	}
	var out []string
	err := x.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM public.authn_accounts
			WHERE tenant_id = $1::uuid AND directory_connection_id = $2::uuid AND directory_object_guid = $3::uuid
			AND state <> 'deleted' ORDER BY id LIMIT $4`, t.String(), ref.ConnectionID, ref.ObjectGUID, MaxBackedAccounts+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authn: accounts backed by object: %w", err)
	}
	if len(out) > MaxBackedAccounts {
		return nil, ErrTooManyAccounts
	}
	return out, nil
}
