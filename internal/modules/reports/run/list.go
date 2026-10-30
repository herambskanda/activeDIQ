package run

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ListFilter filters the history list. The runner is never a parameter: the list is the caller's.
type ListFilter struct {
	State        State // "" for any
	DefinitionID string
	Limit        int
	Cursor       string
}

// Item is one history row: the run and whether its stored result still matches the caller's scope.
type Item struct {
	Run          Run
	ScopeCurrent bool
}

type listCursor struct {
	V  int       `json:"v"`
	At time.Time `json:"a"`
	ID string    `json:"i"`
}

const listRuns = `SELECT ` + runCols + ` FROM public.report_runs
WHERE runner_account = $1::uuid
  AND ($2::text = '' OR state = $2) AND ($3::text = '' OR definition_id = $3)
  AND ($4::timestamptz IS NULL OR (created_at, id) < ($4::timestamptz, $5::uuid))
ORDER BY created_at DESC, id DESC LIMIT $6`

// List is the caller's run history, newest first. It is not a run read, so it does not go through
// ReadAccess; it makes one ReadScopes call per request and sets ScopeCurrent from it (§6.6).
func (s *Service) List(ctx context.Context, tid tenant.ID, chain authority.Chain, f ListFilter) ([]Item, string, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultPageSize
	}
	if limit < 1 || limit > 1000 {
		return nil, "", ErrBadLimit
	}
	var at *time.Time
	after := "00000000-0000-0000-0000-000000000000"
	if f.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		var c listCursor
		if err != nil || json.Unmarshal(b, &c) != nil || c.V != 1 {
			return nil, "", ErrBadCursor
		}
		if _, err := ParseID(c.ID); err != nil {
			return nil, "", ErrBadCursor
		}
		at, after = &c.At, c.ID
	}
	var items []Item
	next := ""
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		scope, err := s.Scopes.For(ctx, tx, tid, chain, Perm)
		if err != nil {
			return err
		}
		fp := scope.Fingerprint()
		rows, err := tx.Query(ctx, listRuns, string(chain.Requester.ID), string(f.State), f.DefinitionID, at, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRun(rows)
			if err != nil {
				return err
			}
			items = append(items, Item{Run: r, ScopeCurrent: r.ScopeFingerprint == fp})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1].Run
		b, _ := json.Marshal(listCursor{V: 1, At: last.CreatedAt, ID: last.ID.String()})
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	return items, next, nil
}

// EffectiveState reports a succeeded run past its expiry as expired, which is what a reader meets even
// before the retention sweep flips the record.
func (r Run) EffectiveState(now time.Time) State {
	if r.State == StateSucceeded && r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
		return StateExpired
	}
	return r.State
}
