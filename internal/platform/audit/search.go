package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Search limits. A page is bounded by rows examined as well as by rows matched, so a filter that matches
// nothing cannot make one request read a tenant's whole chain.
const (
	DefaultSearchLimit = 100
	MaxSearchLimit     = 500
	// SearchScanCap is the most rows one Search examines.
	SearchScanCap = 5000
	scanBatch     = 500
)

// ErrBadSearch is returned for a query with a limit out of range or an inverted time window.
var ErrBadSearch = errors.New("audit: invalid search")

// SearchQuery filters the tenant's chain. Every field is optional; all given fields must match. Each is a
// typed value compared in Go or bound as a parameter: nothing here is a filter string.
type SearchQuery struct {
	DC           string    // the "dc" public detail, matched case-insensitively
	CredentialID string    // the "credential_id" public detail, exact
	Target       string    // the target objectGUID, canonical lower-case text
	From, To     time.Time // [From, To); a zero value is unbounded
	AfterSeq     uint64    // resume after this chain position
	Limit        int       // 0 is DefaultSearchLimit
}

// SearchPage is one page. Next is the position to resume after; 0 means the chain is exhausted for this query.
// A page may hold fewer than Limit events, or none, and still have a Next.
type SearchPage struct {
	Events []chain.Envelope
	Next   uint64
}

// Search reads one page of the chain of id in tx (a tenant transaction), oldest first.
func Search(ctx context.Context, tx store.Tx, id tenant.ID, q SearchQuery) (SearchPage, error) {
	limit := q.Limit
	if limit == 0 {
		limit = DefaultSearchLimit
	}
	if limit < 0 || limit > MaxSearchLimit || (!q.From.IsZero() && !q.To.IsZero() && !q.From.Before(q.To)) {
		return SearchPage{}, ErrBadSearch
	}
	var from, to *time.Time
	if !q.From.IsZero() {
		from = &q.From
	}
	if !q.To.IsZero() {
		to = &q.To
	}
	var page SearchPage
	after, scanned := q.AfterSeq, 0
	for scanned < SearchScanCap {
		rows, err := tx.Query(ctx, `SELECT seq, envelope FROM audit_event
WHERE tenant_id = $1::uuid AND seq > $2 AND ($3::timestamptz IS NULL OR at >= $3) AND ($4::timestamptz IS NULL OR at < $4)
ORDER BY seq LIMIT $5`, id.String(), after, from, to, scanBatch)
		if err != nil {
			return SearchPage{}, fmt.Errorf("audit: search: %w", err)
		}
		n := 0
		for rows.Next() {
			var seq uint64
			var raw []byte
			if err := rows.Scan(&seq, &raw); err != nil {
				rows.Close()
				return SearchPage{}, fmt.Errorf("audit: search: %w", err)
			}
			n++
			scanned++
			after = seq
			env, err := chain.ParseEnvelope(raw)
			if err != nil {
				rows.Close()
				return SearchPage{}, fmt.Errorf("audit: search: event %d: %w", seq, err)
			}
			env.Seq = seq
			if q.matches(env) {
				page.Events = append(page.Events, env)
				if len(page.Events) == limit {
					rows.Close()
					page.Next = after
					return page, nil
				}
			}
		}
		if err := rows.Err(); err != nil {
			return SearchPage{}, fmt.Errorf("audit: search: %w", err)
		}
		rows.Close()
		if n < scanBatch {
			return page, nil // the chain is exhausted for this window
		}
	}
	page.Next = after // scan cap reached: more may remain
	return page, nil
}

func (q SearchQuery) matches(e chain.Envelope) bool {
	if q.Target != "" && !strings.EqualFold(e.TargetGUID, q.Target) {
		return false
	}
	if q.DC != "" && !strings.EqualFold(DetailValue(e, "dc"), q.DC) {
		return false
	}
	if q.CredentialID != "" && DetailValue(e, "credential_id") != q.CredentialID {
		return false
	}
	return true
}

// DetailValue returns the public detail key of e, or "".
func DetailValue(e chain.Envelope, key string) string {
	for _, d := range e.Details {
		if d.Key == key {
			return d.Value
		}
	}
	return ""
}
