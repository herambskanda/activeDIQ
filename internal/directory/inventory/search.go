package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The search port (ADR-0011 rules 8, 11-13). The statement is compiled by reportsql.CompileSearch, which
// draws the caller's scope with the one scope renderer, so the hits come back trimmed: this package never
// hands ancestry to a caller to trim with.

const (
	// DefaultSearchCeiling is W: matched key rows per class above which a class is withheld and the
	// caller is told to refine. [PROPOSED] 10,000; T-1102 measures and sets it.
	DefaultSearchCeiling = 10000
	// searchThreshold is pg_trgm.word_similarity_threshold for the fuzzy class. Tuned on the 'Pryia Ramn'
	// vector (T-1095): its word_similarity to 'priya raman' is 0.333 on pg16 and pg18, a transposition
	// costing four trigrams, so 0.5 cannot find it; the nearest unrelated name measured ('praveen
	// ramesh') scores 0.294. Ranking by similarity and the ceiling bound the extra candidates.
	searchThreshold = 0.3
)

// ErrSearchRefused: the search text is refused (rule 7). It carries no text.
var ErrSearchRefused = errors.New("inventory: search text refused")

// SearchRequest is one search.
type SearchRequest struct {
	// Text is the user's text. Search classifies it with searchkey, so the text and the keys cannot drift.
	Text string
	// Types is the facet; empty means users, groups, computers and contacts.
	Types []reportsql.SearchType
	// GroupLimit is the hits per group, 1..50 (default 5).
	GroupLimit int
	// After, when set, is a verified keyset position (the caller checks its MAC).
	After *reportsql.SearchAfter
}

// SearchResult is reportsql's: trimmed hits, the refine state, and counts only when they are exact.
type SearchResult = reportsql.SearchResult

// Searcher is the search port's implementation. W (the ceiling) is fixed when it is built and is not a
// request property: whether a class is withheld must depend only on the tenant's data, never on a value
// the caller chose (ADR-0011 rules 12-13, T-0995 leak class).
type Searcher struct {
	src     reportsql.SearchSource
	ceiling int
}

// SearcherOption configures a Searcher at construction.
type SearcherOption func(*Searcher)

// WithCeiling sets W for every search the Searcher answers (compose config, T-1102). NewSearcher refuses
// a value outside 1..reportsql.MaxSearchCeiling.
func WithCeiling(w int) SearcherOption { return func(s *Searcher) { s.ceiling = w } }

// NewSearcher registers the search source against the live schema, as the datasets are.
func NewSearcher(sch reportsql.Schema, opts ...SearcherOption) (*Searcher, error) {
	src, err := reportsql.NewSearchSource(sch, "inventory_search_keys", report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor,
		Project: idents("object_guid"), Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid",
		Ancestry: "ancestry", Complete: "ancestry_complete"}, "kind", "state", "enabled", "display_name")
	if err != nil {
		return nil, fmt.Errorf("inventory: search source: %w", err)
	}
	s := &Searcher{src: src, ceiling: DefaultSearchCeiling}
	for _, o := range opts {
		o(s)
	}
	if s.ceiling < 1 || s.ceiling > reportsql.MaxSearchCeiling {
		return nil, fmt.Errorf("inventory: search ceiling %d outside 1..%d", s.ceiling, reportsql.MaxSearchCeiling)
	}
	return s, nil
}

// Search answers exact, prefix and fuzzy lookups over the tenant's users, groups, computers and contacts,
// trimmed to scopes in the statement itself. tx is the caller's tenant transaction (its statement timeout
// is the safety net of rule 13); tid must be the tenant of tx. Search text is never logged or echoed.
func (s *Searcher) Search(ctx context.Context, tx store.Tx, tid tenant.ID, scopes reportsql.SearchScopes, req SearchRequest) (SearchResult, error) {
	if s == nil {
		return SearchResult{}, ErrNotConfigured
	}
	if tid.IsZero() {
		return SearchResult{}, ErrNoTenant
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT NULLIF(current_setting('app.tenant_id', true), '') = $1`, tid.String()).Scan(&ok); err != nil {
		return SearchResult{}, fmt.Errorf("inventory: tenant context: %w", err)
	}
	if !ok {
		return SearchResult{}, ErrNoTenant
	}
	p, err := searchkey.Classify(req.Text)
	if err != nil {
		return SearchResult{}, fmt.Errorf("%w: %w", ErrSearchRefused, err)
	}
	q := reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, Types: req.Types, GroupLimit: req.GroupLimit, Ceiling: s.ceiling, After: req.After, Threshold: searchThreshold}
	if q.GroupLimit == 0 {
		q.GroupLimit = 5
	}
	cq, err := reportsql.CompileSearch(s.src, q, scopes)
	if err != nil {
		return SearchResult{}, err
	}
	res, err := reportsql.ExecSearch(ctx, tx, cq)
	if err != nil {
		return SearchResult{}, err
	}
	// Counts are shown only from three characters (rule 12).
	if p.Runes < 3 {
		res.Count = nil
	}
	return res, nil
}
