package inventory

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_recent_objects", Entity: "DM-16", Kind: tablekind.Directory})

// Per-account recent objects (T-1130, ADR-0011 rule 8). A row says an account opened an object page; it
// grants nothing. Every read goes through reportsql, which trims by the account's current ReadScope in the
// same statement, so an object that has left the scope is never listed.

// ErrNoAccount: the account is not a uuid. Recents belong to a human account, never to a token.
var ErrNoAccount = errors.New("inventory: recents need an account")

// ErrUnknownObject: the object is not in this tenant's inventory (nothing is remembered).
var ErrUnknownObject = errors.New("inventory: object not in the inventory")

var uuidForm = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isUUID(s string) bool { return uuidForm.MatchString(s) }

// IsAccountID reports whether s has the form the recents store accepts for an account.
func IsAccountID(s string) bool { return isUUID(s) }

const (
	recentUpsert = `INSERT INTO public.inventory_recent_objects (tenant_id, account_id, connection_id, object_guid, opened_at)
SELECT d.tenant_id, $1::uuid, d.connection_id, d.object_guid, $4
FROM public.directory_objects d
WHERE d.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND d.connection_id = $2::uuid AND d.object_guid = $3::uuid
ON CONFLICT (tenant_id, account_id, connection_id, object_guid) DO UPDATE SET opened_at = EXCLUDED.opened_at`
	// recentTrim keeps the newest $2 rows of the account.
	recentTrim = `DELETE FROM public.inventory_recent_objects
WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND account_id = $1::uuid
AND (connection_id, object_guid) NOT IN (
  SELECT connection_id, object_guid FROM public.inventory_recent_objects
  WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND account_id = $1::uuid
  ORDER BY opened_at DESC, connection_id, object_guid LIMIT $2)`
)

// RecordOpened remembers that the account opened the object, moving it to the front, and keeps only the
// newest reportsql.MaxRecents of the account, in the caller's tenant transaction. The caller has already
// authorised the page view; nothing here widens what the account can read.
func (s *Searcher) RecordOpened(ctx context.Context, tx store.Tx, tid tenant.ID, account, connection, object string, now time.Time) error {
	if s == nil {
		return ErrNotConfigured
	}
	if !isUUID(account) {
		return ErrNoAccount
	}
	if err := checkTenant(ctx, tx, tid); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, recentUpsert, account, connection, object, now.UTC())
	if err != nil {
		return fmt.Errorf("inventory: record recent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUnknownObject
	}
	if _, err := tx.Exec(ctx, recentTrim, account, reportsql.MaxRecents); err != nil {
		return fmt.Errorf("inventory: trim recents: %w", err)
	}
	return nil
}

// Recents lists the account's recent objects, newest first, trimmed to scopes and grouped like a search
// (the empty palette). An empty list is a real answer: nothing is invented.
func (s *Searcher) Recents(ctx context.Context, tx store.Tx, tid tenant.ID, scopes reportsql.SearchScopes, account string, types []reportsql.SearchType, groupLimit int) (SearchResult, error) {
	if s == nil {
		return SearchResult{}, ErrNotConfigured
	}
	if !isUUID(account) {
		return SearchResult{}, ErrNoAccount
	}
	if err := checkTenant(ctx, tx, tid); err != nil {
		return SearchResult{}, err
	}
	if groupLimit == 0 {
		groupLimit = 5
	}
	cq, err := reportsql.CompileSearch(s.src, reportsql.SearchQuery{Types: types, GroupLimit: groupLimit, Ceiling: s.ceiling, Account: account, RecentsOnly: true}, scopes)
	if err != nil {
		return SearchResult{}, err
	}
	res, err := reportsql.ExecSearch(ctx, tx, cq)
	if err != nil {
		return SearchResult{}, err
	}
	// A count of a list the account built itself is not a statement about the directory.
	res.Count = nil
	return res, nil
}
